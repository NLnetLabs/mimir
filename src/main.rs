//! DNS proxy

//#![warn(missing_docs)]
//#![warn(clippy::missing_docs_in_private_items)]

use clap::Parser;
use domain::base::wire::Composer;
use domain::base::Name;
use domain::net::client::protocol::{TcpConnect, TlsConnect, UdpConnect};
use domain::net::client::request::{
    ComposeRequest, RequestMessage, SendRequest,
};
use domain::net::client::{
    cache, dgram, dgram_stream, load_balancer, multi_stream, redundant,
    validator,
};
use domain::net::server;
use domain::net::server::adapter::BoxClientTransportToSingleService;
use domain::net::server::adapter::ClientTransportToSingleService;
use domain::net::server::adapter::SingleServiceToService;
use domain::net::server::buf::BufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::qname_router::QnameRouter;
use domain::net::server::service::Service;
use domain::net::server::single_service::ComposeReply;
use domain::net::server::single_service::ReplyMessage;
use domain::net::server::single_service::SingleService;
use domain::net::server::sock::AsyncAccept;
use domain::net::server::stream::StreamServer;
use domain::validator::anchor::TrustAnchors;
use domain::validator::context::ValidationContext;
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::bool_true;
use std::fmt::Debug;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio_rustls::rustls;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsAcceptor;

const IANA_TRUST_ANCHOR: &str = "
. IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
. IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16
";

/// Arguments parser.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Configuration
    config: String,
}

/// Top level configuration structure.
#[derive(Debug, Deserialize, Serialize)]
struct Config {
    server: ServerConfig,

    /// Config for upstream connections
    upstream: TopUpstreamConfig,
}

#[derive(Debug, Deserialize, Serialize)]
struct ServerConfig {
    listen: Vec<ListenConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum ListenConfig {
    #[serde(rename = "UDP+TCP")]
    UdpTcp(SimpleListenConfig),

    #[serde(rename = "UDP-only")]
    Udp(SimpleListenConfig),

    #[serde(rename = "TCP")]
    Tcp(SimpleListenConfig),

    #[serde(rename = "TLS")]
    Tls(TlsListenConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct SimpleListenConfig {
    port: Option<u16>,
    addr: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TlsListenConfig {
    port: Option<u16>,
    addr: Option<String>,
    certificate: String,
    key: String,
}

/// Configure for upstream config at the top level.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum TopUpstreamConfig {
    /// Qname router
    #[serde(rename = "qname-router")]
    Qname(QnameConfig),

    /// Redudant upstreams
    #[serde(rename = "redundant")]
    Redundant(CacheValidatorRedundantConfig),

    /// Load balancer
    #[serde(rename = "lb")]
    LoadBalancer(CacheValidatorLoadBalancerConfig),

    /// TCP upstream
    #[serde(rename = "TCP")]
    Tcp(CacheValidatorTcpConfig),

    /// TLS upstream
    #[serde(rename = "TLS")]
    Tls(CacheValidatorTlsConfig),

    /// UDP upstream that does not switch to TCP when the reply is truncated
    #[serde(rename = "UDP-only")]
    Udp(CacheValidatorUdpConfig),

    /// UDP upstream that switchs to TCP when the reply is truncated
    #[serde(rename = "UDP")]
    UdpTcp(CacheValidatorUdpTcpConfig),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct QnameRouterConfig;

/// Configure for client transports
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum FullTransportConfig {
    /// Redudant upstreams
    #[serde(rename = "redundant")]
    Redundant(RedundantConfig),

    /// Load balancer
    #[serde(rename = "lb")]
    LoadBalancer(LoadBalancerConfig),

    /// TCP upstream
    #[serde(rename = "TCP")]
    Tcp(TcpConfig),

    /// TLS upstream
    #[serde(rename = "TLS")]
    Tls(TlsConfig),

    /// UDP upstream that does not switch to TCP when the reply is truncated
    #[serde(rename = "UDP-only")]
    Udp(UdpConfig),

    /// UDP upstream that switchs to TCP when the reply is truncated
    #[serde(rename = "UDP")]
    UdpTcp(UdpTcpConfig),
}

/// Configure for client transports
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum QrTransportConfig {
    /// Redudant upstreams
    #[serde(rename = "redundant")]
    Redundant(CacheValidatorRedundantConfig),

    /// Load balancer
    #[serde(rename = "lb")]
    LoadBalancer(CacheValidatorLoadBalancerConfig),

    /// TCP upstream
    #[serde(rename = "TCP")]
    Tcp(TcpConfig),

    /// TLS upstream
    #[serde(rename = "TLS")]
    Tls(TlsConfig),

    /// UDP upstream that does not switch to TCP when the reply is truncated
    #[serde(rename = "UDP-only")]
    Udp(UdpConfig),

    /// UDP upstream that switchs to TCP when the reply is truncated
    #[serde(rename = "UDP")]
    UdpTcp(UdpTcpConfig),
}

/// Configure for client transports
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
enum TransportConfig {
    /// TCP upstream
    #[serde(rename = "TCP")]
    Tcp(TcpConfig),

    /// TLS upstream
    #[serde(rename = "TLS")]
    Tls(TlsConfig),

    /// UDP upstream that does not switch to TCP when the reply is truncated
    #[serde(rename = "UDP-only")]
    Udp(UdpConfig),

    /// UDP upstream that switchs to TCP when the reply is truncated
    #[serde(rename = "UDP")]
    UdpTcp(UdpTcpConfig),
}

/// Config for a Qname router
#[derive(Clone, Debug, Deserialize, Serialize)]
struct QnameConfig {
    /// List of transports to be used by a Qname router
    domains: Vec<QnameDomain>,
}

/// Config for a Qname-routed domain
#[derive(Clone, Debug, Deserialize, Serialize)]
struct QnameDomain {
    /// Name of the domain
    name: String,
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    upstream: FullTransportConfig,
}

/// Config for a cached transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheConfig {
    #[serde(default = "bool_true")]
    enabled: bool,
}

/// Config for a validator transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ValidatorConfig {
    #[serde(default = "bool_true")]
    enabled: bool,
    #[serde(rename = "trust-anchor")]
    trust_anchor: Option<String>,
}

/// Config for a redundant transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RedundantConfig {
    /// List of upstream configs.
    upstreams: Vec<RedundantUpstreamConfig>,
}

/// Config for a redundant transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorRedundantConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// List of upstream configs.
    upstreams: Vec<RedundantUpstreamConfig>,
}

/// Config for a redundant upstream
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RedundantUpstreamConfig {
    upstream: TransportConfig,
}

/// Config for a load balancer transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LoadBalancerConfig {
    /// List of upstream configs.
    upstreams: Vec<LBUpstreamConfig>,
}

/// Config for a load balancer transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorLoadBalancerConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// List of upstream configs.
    upstreams: Vec<LBUpstreamConfig>,
}

/// Config for a load balancer upstream
#[derive(Clone, Debug, Deserialize, Serialize)]
struct LBUpstreamConfig {
    label: String,
    /// Maximum allowed burst for upstream.
    #[serde(rename = "max-burst")]
    max_burst: Option<u64>,
    #[serde(rename = "burst-interval")]
    burst_interval: Option<f64>,
    upstream: TransportConfig,
}

/// Config for a TCP transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TcpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a TCP transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorTcpConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a TLS transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct TlsConfig {
    /// Name of the remote resolver
    servername: String,

    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a TLS transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorTlsConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// Name of the remote resolver
    servername: String,

    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP-only transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct UdpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP-only transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorUdpConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP+TCP transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct UdpTcpConfig {
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// Config for a UDP+TCP transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheValidatorUdpTcpConfig {
    cache: Option<CacheConfig>,
    validator: Option<ValidatorConfig>,
    /// Address of the remote resolver
    addr: String,

    /// Optional port
    port: Option<String>,
}

/// A buffer based on Vec.
struct VecBufSource;

impl BufSource for VecBufSource {
    type Output = Vec<u8>;

    fn create_buf(&self) -> Self::Output {
        vec![0; 1024]
    }

    fn create_sized(&self, size: usize) -> Self::Output {
        vec![0; size]
    }
}

/// Vector of octets
type VecU8 = Vec<u8>;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let mut f = File::open(&args.config).unwrap();
    let conf: Config = if args.config.ends_with(".json") {
        serde_json::from_reader(f).unwrap()
    } else {
        let mut str = String::new();
        f.read_to_string(&mut str).unwrap();
        toml::from_str(&str).unwrap()
    };

    println!("Got: {:?}", conf);

    let toml = toml::to_string(&conf).unwrap();

    println!("Got toml:\n{toml}");

    // We cannot use get_transport because we cannot pass a Box<dyn ...> to
    // query_service because it lacks Clone.
    let join_handles = match &conf.upstream {
        TopUpstreamConfig::Qname(qname_conf) => {
            let qr = get_qname_router::<ReplyMessage>(qname_conf).await;
            start_single_service(qr, &conf.server).await
        }
        TopUpstreamConfig::Redundant(redun_conf) => {
            let redun = get_cv_redundant(redun_conf).await;
            start_cache_validator_service(
                &redun_conf.cache,
                &redun_conf.validator,
                redun,
                &conf.server,
            )
            .await
        }
        TopUpstreamConfig::LoadBalancer(lb_conf) => {
            let lb = get_cv_lb(lb_conf).await;
            start_cache_validator_service(
                &lb_conf.cache,
                &lb_conf.validator,
                lb,
                &conf.server,
            )
            .await
        }
        TopUpstreamConfig::Tcp(tcp_conf) => {
            let tcp = get_cv_tcp::<RequestMessage<VecU8>>(tcp_conf);
            start_cache_validator_service(
                &tcp_conf.cache,
                &tcp_conf.validator,
                tcp,
                &conf.server,
            )
            .await
        }
        TopUpstreamConfig::Tls(tls_conf) => {
            let tls = get_cv_tls::<RequestMessage<VecU8>>(tls_conf);
            start_cache_validator_service(
                &tls_conf.cache,
                &tls_conf.validator,
                tls,
                &conf.server,
            )
            .await
        }
        TopUpstreamConfig::Udp(udp_conf) => {
            let udp = get_cv_udp::<RequestMessage<VecU8>>(udp_conf);
            start_cache_validator_service(
                &udp_conf.cache,
                &udp_conf.validator,
                udp,
                &conf.server,
            )
            .await
        }
        TopUpstreamConfig::UdpTcp(udptcp_conf) => {
            let udptcp = get_cv_udptcp::<RequestMessage<VecU8>>(udptcp_conf);
            start_cache_validator_service(
                &udptcp_conf.cache,
                &udptcp_conf.validator,
                udptcp,
                &conf.server,
            )
            .await
        }
    };

    for j in join_handles {
        println!("Waiting {:?}", j);
        let res = j.await;
        println!("Got res {:?}", res);
    }
}

/// Get a qname router based on its config
async fn get_qname_router<CR>(
    config: &QnameConfig,
) -> QnameRouter<Vec<u8>, VecU8, CR>
where
    CR: ComposeReply + Send + Sync + 'static,
{
    println!("Creating new QnameRouter");
    let mut qr = QnameRouter::new();
    println!("Adding to QnameRouter");
    for e in &config.domains {
        println!("Add to QnameRouter");
        let transp =
            get_qr_transport(&e.upstream, &e.cache, &e.validator).await;
        let svc = BoxClientTransportToSingleService::new(transp);
        qr.add(Name::<Vec<u8>>::from_str(&e.name).unwrap(), svc);
        println!("After Add to QnameRouter");
    }
    qr
}

/// Get a redundant transport based on its config
async fn get_redun(
    config: &RedundantConfig,
) -> redundant::Connection<RequestMessage<VecU8>> {
    get_redun_common(&config.upstreams).await
}

/// Get a redundant transport based on its config.
///
/// The config used is the CacheValidatorRedundantConfig but the cache and
/// validator parts of the config are ignored.
async fn get_cv_redundant(
    config: &CacheValidatorRedundantConfig,
) -> redundant::Connection<RequestMessage<VecU8>> {
    get_redun_common(&config.upstreams).await
}

async fn get_redun_common(
    upstreams: &[RedundantUpstreamConfig],
) -> redundant::Connection<RequestMessage<VecU8>> {
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    for e in upstreams {
        redun.add(get_simple_transport(&e.upstream)).await.unwrap();
    }
    redun
}

/// Get a load balanced transport based on its config
async fn get_lb(
    config: &LoadBalancerConfig,
) -> load_balancer::Connection<RequestMessage<VecU8>> {
    get_lb_common(&config.upstreams).await
}

/// Get a load balanced transport based on its config
///
/// The config used is the CacheValidatorLoadBalancerConfig but the cache and
/// validator parts of the config are ignored.
async fn get_cv_lb(
    config: &CacheValidatorLoadBalancerConfig,
) -> load_balancer::Connection<RequestMessage<VecU8>> {
    get_lb_common(&config.upstreams).await
}

async fn get_lb_common(
    upstreams: &[LBUpstreamConfig],
) -> load_balancer::Connection<RequestMessage<VecU8>> {
    let (lb, transport) = load_balancer::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    for e in upstreams {
        let mut conf = load_balancer::ConnConfig::new();
        conf.set_max_burst(e.max_burst);
        if let Some(f) = e.burst_interval {
            conf.set_burst_interval(Duration::from_secs_f64(f));
        }
        lb.add(&e.label, &conf, get_simple_transport(&e.upstream))
            .await
            .unwrap();
    }
    lb
}

/// Get a TCP transport based on its config
fn get_tcp<CR: ComposeRequest + Clone + 'static>(
    config: &TcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_tcp_common(&config.addr, &config.port)
}

/// Get a TCP transport based on its config
///
/// The config used is the CacheValidatorTcpConfig, but the cache and
/// validator parts of the config are ignored.
fn get_cv_tcp<CR: ComposeRequest + Clone + 'static>(
    config: &CacheValidatorTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_tcp_common(&config.addr, &config.port)
}

fn get_tcp_common<CR: ComposeRequest + Clone + 'static>(
    addr: &str,
    port: &Option<String>,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(addr, port.as_deref(), 53);
    let tcp_connect = TcpConnect::new(sockaddr);

    let (conn, transport) = multi_stream::Connection::new(tcp_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });

    conn
}

/// Get a TLS transport based on its config
fn get_tls<CR: ComposeRequest + Clone + 'static>(
    config: &TlsConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_tls_common(&config.addr, &config.port, &config.servername)
}

/// Get a TLS transport based on its config
///
/// The config used is the CacheValidatorTlsConfig, but the cache and
/// validator parts of the config are ignored.
fn get_cv_tls<CR: ComposeRequest + Clone + 'static>(
    config: &CacheValidatorTlsConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_tls_common(&config.addr, &config.port, &config.servername)
}

fn get_tls_common<CR: ComposeRequest + Clone + 'static>(
    addr: &str,
    port: &Option<String>,
    servername: &str,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(addr, port.as_deref(), 853);

    // Some TLS boiler plate for the root certificates.
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_connect = TlsConnect::new(
        client_config,
        String::from(servername).try_into().unwrap(),
        sockaddr,
    );
    let (conn, transport) = multi_stream::Connection::new(tls_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });

    conn
}

/// Get a UDP-only transport based on its config
fn get_udp<CR: ComposeRequest + Clone + 'static>(
    config: &UdpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_udp_common(&config.addr, &config.port)
}

/// Get a UDP-only transport based on its config
///
/// The config used is the CacheValidatorUdpConfig, but the cache and
/// validator parts of the config are ignored.
fn get_cv_udp<CR: ComposeRequest + Clone + 'static>(
    config: &CacheValidatorUdpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_udp_common(&config.addr, &config.port)
}

fn get_udp_common<CR: ComposeRequest + Clone + 'static>(
    addr: &str,
    port: &Option<String>,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(addr, port.as_deref(), 53);

    let udp_connect = UdpConnect::new(sockaddr);
    dgram::Connection::new(udp_connect)
}

/// Get a UDP+TCP transport based on its config
fn get_udptcp<CR: ComposeRequest + Clone + Debug + 'static>(
    config: &UdpTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_udptcp_common(&config.addr, &config.port)
}

/// Get a UDP+TCP transport based on its config
///
/// The config used is the CacheValidatorUdpTcpConfig, but the cache and
/// validator parts of the config are ignored.
fn get_cv_udptcp<CR: ComposeRequest + Clone + Debug + 'static>(
    config: &CacheValidatorUdpTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    get_udptcp_common(&config.addr, &config.port)
}

fn get_udptcp_common<CR: ComposeRequest + Clone + Debug + 'static>(
    addr: &str,
    port: &Option<String>,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(addr, port.as_deref(), 53);
    let udp_connect = UdpConnect::new(sockaddr);
    let tcp_connect = TcpConnect::new(sockaddr);
    let (conn, transport) =
        dgram_stream::Connection::new(udp_connect, tcp_connect);
    tokio::spawn(async move {
        transport.run().await;
        println!("run terminated");
    });
    conn
}

/// Get a transport based on its config
async fn get_qr_transport(
    config: &FullTransportConfig,
    cache_conf: &Option<CacheConfig>,
    validator_conf: &Option<ValidatorConfig>,
) -> Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> {
    let config = config.clone();
    println!("got config {:?}", config);
    let a: Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> =
        match config {
            FullTransportConfig::Redundant(redun_conf) => {
                let conn = get_redun(&redun_conf).await;
                box_cache_validator(cache_conf, validator_conf, conn)
            }
            FullTransportConfig::LoadBalancer(lb_conf) => {
                let conn = get_lb(&lb_conf).await;
                box_cache_validator(cache_conf, validator_conf, conn)
            }
            FullTransportConfig::Tcp(tcp_conf) => {
                let conn = get_tcp(&tcp_conf);
                box_cache_validator(cache_conf, validator_conf, conn)
            }
            FullTransportConfig::Tls(tls_conf) => {
                let conn = get_tls(&tls_conf);
                box_cache_validator(cache_conf, validator_conf, conn)
            }
            FullTransportConfig::Udp(udp_conf) => {
                let conn = get_udp(&udp_conf);
                box_cache_validator(cache_conf, validator_conf, conn)
            }
            FullTransportConfig::UdpTcp(udptcp_conf) => {
                let conn = get_udptcp(&udptcp_conf);
                box_cache_validator(cache_conf, validator_conf, conn)
            }
        };
    a
}

/// Get a transport based on its config
fn get_simple_transport(
    config: &TransportConfig,
) -> Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> {
    let config = config.clone();
    println!("got config {:?}", config);
    let a: Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> =
        match config {
            TransportConfig::Tcp(tcp_conf) => Box::new(get_tcp(&tcp_conf)),
            TransportConfig::Tls(tls_conf) => Box::new(get_tls(&tls_conf)),
            TransportConfig::Udp(udp_conf) => Box::new(get_udp(&udp_conf)),
            TransportConfig::UdpTcp(udptcp_conf) => {
                Box::new(get_udptcp(&udptcp_conf))
            }
        };
    a
}

#[allow(clippy::type_complexity)]
fn build_middleware_chain<Svc>(
    svc: Svc,
) -> MandatoryMiddlewareSvc<
    Vec<u8>,
    EdnsMiddlewareSvc<Vec<u8>, CookiesMiddlewareSvc<Vec<u8>, Svc, ()>, ()>,
    (),
> {
    let svc = CookiesMiddlewareSvc::<Vec<u8>, _, _>::with_random_secret(svc);
    let svc = EdnsMiddlewareSvc::<Vec<u8>, _, _>::new(svc);
    MandatoryMiddlewareSvc::<Vec<u8>, _, _>::new(svc)
}

fn box_cache_validator(
    cache_conf: &Option<CacheConfig>,
    validator_conf: &Option<ValidatorConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
) -> Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> {
    match validator_conf {
        Some(validator_conf) => {
            if validator_conf.enabled {
                let ta = if let Some(file) = &validator_conf.trust_anchor {
                    let anchor_file = File::open(file).unwrap();
                    TrustAnchors::from_reader(anchor_file).unwrap()
                } else {
                    TrustAnchors::from_u8(IANA_TRUST_ANCHOR.as_bytes())
                        .unwrap()
                };
                let vc = Arc::new(ValidationContext::new(ta, conn.clone()));
                let conn = validator::Connection::new(conn, vc);
                box_cache(cache_conf, conn)
            } else {
                box_cache(cache_conf, conn)
            }
        }
        None => box_cache(cache_conf, conn),
    }
}

fn box_cache(
    cache_conf: &Option<CacheConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
) -> Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> {
    match cache_conf {
        Some(cache_conf) => {
            if cache_conf.enabled {
                let conn = cache::Connection::new(conn);
                Box::new(conn)
            } else {
                Box::new(conn)
            }
        }
        None => Box::new(conn),
    }
}

//--- RustlsTcpListener

struct RustlsTcpListener {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl RustlsTcpListener {
    pub fn new(
        listener: TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> Self {
        Self { listener, acceptor }
    }
}

impl AsyncAccept for RustlsTcpListener {
    type Error = io::Error;
    type StreamType = tokio_rustls::server::TlsStream<TcpStream>;
    type Future = tokio_rustls::Accept<TcpStream>;

    #[allow(clippy::type_complexity)]
    fn poll_accept(
        &self,
        cx: &mut Context,
    ) -> Poll<Result<(Self::Future, SocketAddr), io::Error>> {
        TcpListener::poll_accept(&self.listener, cx).map(|res| {
            res.map(|(stream, addr)| (self.acceptor.accept(stream), addr))
        })
    }
}

async fn start_cache_validator_service(
    cache_conf: &Option<CacheConfig>,
    validator_conf: &Option<ValidatorConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    server_config: &ServerConfig,
) -> Vec<JoinHandle<()>> {
    match validator_conf {
        Some(validator_conf) => {
            if validator_conf.enabled {
                let ta = if let Some(file) = &validator_conf.trust_anchor {
                    let anchor_file = File::open(file).unwrap();
                    TrustAnchors::from_reader(anchor_file).unwrap()
                } else {
                    TrustAnchors::from_u8(IANA_TRUST_ANCHOR.as_bytes())
                        .unwrap()
                };
                let vc = Arc::new(ValidationContext::new(ta, conn.clone()));
                let conn = validator::Connection::new(conn, vc);
                start_cache_service(cache_conf, conn, server_config).await
            } else {
                start_cache_service(cache_conf, conn, server_config).await
            }
        }
        None => start_cache_service(cache_conf, conn, server_config).await,
    }
}

async fn start_cache_service(
    cache_conf: &Option<CacheConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    server_config: &ServerConfig,
) -> Vec<JoinHandle<()>> {
    match cache_conf {
        Some(cache_conf) => {
            if cache_conf.enabled {
                let conn = cache::Connection::new(conn);
                start_conn_service(conn, server_config).await
            } else {
                start_conn_service(conn, server_config).await
            }
        }
        None => start_conn_service(conn, server_config).await,
    }
}

/// Start a service based on a transport, a UDP server socket and a buffer
async fn start_conn_service(
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    server_config: &ServerConfig,
) -> Vec<JoinHandle<()>>
where
{
    //let svc = MyService::new(conn);
    let svc = ClientTransportToSingleService::new(conn);
    let svc = SingleServiceToService::<_, _, ReplyMessage>::new(svc);

    let svc = Arc::new(build_middleware_chain(svc));

    start_service(svc, server_config).await
}

async fn start_service<SVC>(
    svc: SVC,
    config: &ServerConfig,
) -> Vec<JoinHandle<()>>
where
    SVC: Service + Clone + Send + Sync + 'static,
    SVC::Future: Send,
    SVC::Stream: Send,
    SVC::Target: Composer + Default + Send + Sync,
{
    let mut handles = Vec::new();

    for l in &config.listen {
        match l {
            ListenConfig::UdpTcp(sl_config) => handles.append(
                &mut start_service_udp_tcp(
                    sl_config,
                    true,
                    true,
                    svc.clone(),
                )
                .await,
            ),
            ListenConfig::Udp(sl_config) => handles.append(
                &mut start_service_udp_tcp(
                    sl_config,
                    true,
                    false,
                    svc.clone(),
                )
                .await,
            ),
            ListenConfig::Tcp(sl_config) => handles.append(
                &mut start_service_udp_tcp(
                    sl_config,
                    false,
                    true,
                    svc.clone(),
                )
                .await,
            ),
            ListenConfig::Tls(sl_config) => {
                let locport = sl_config.port.unwrap_or(53);
                let sockaddr = SocketAddr::new(
                    match &sl_config.addr {
                        Some(addr) => addr.parse(),
                        None => "::1".parse(),
                    }
                    .unwrap(),
                    locport,
                );
                let buf_source = Arc::new(VecBufSource);

                let mut handles = Vec::new();

                let file = match File::open(&sl_config.certificate) {
                    Ok(file) => file,
                    Err(e) => panic!(
                        "Unable to open certificate file {}: {e}",
                        sl_config.certificate
                    ),
                };
                let certs = rustls_pemfile::certs(&mut BufReader::new(file))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();

                let file = match File::open(&sl_config.key) {
                    Ok(file) => file,
                    Err(e) => panic!(
                        "Unable to open key file {}: {e}",
                        sl_config.key
                    ),
                };
                let key =
                    rustls_pemfile::private_key(&mut BufReader::new(file))
                        .unwrap()
                        .unwrap();

                let config = rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .unwrap();

                let acceptor = TlsAcceptor::from(Arc::new(config));
                let listener = TcpListener::bind(sockaddr).await.unwrap();
                let listener = RustlsTcpListener::new(listener, acceptor);

                let conn_config = server::ConnectionConfig::new();
                let mut config = server::stream::Config::new();
                config.set_connection_config(conn_config);
                let srv = StreamServer::with_config(
                    listener,
                    buf_source,
                    svc.clone(),
                    config,
                );
                let srv = Arc::new(srv);
                handles.push(tokio::spawn(async move { srv.run().await }));
            }
        }
    }

    handles
}

async fn start_service_udp_tcp<SVC>(
    sl_config: &SimpleListenConfig,
    do_udp: bool,
    do_tcp: bool,
    svc: SVC,
) -> Vec<JoinHandle<()>>
where
    SVC: Service + Clone + Send + Sync + 'static,
    SVC::Future: Send,
    SVC::Stream: Send,
    SVC::Target: Composer + Default + Send + Sync,
{
    let locport = sl_config.port.unwrap_or(53);
    let sockaddr = SocketAddr::new(
        match &sl_config.addr {
            Some(addr) => addr.parse(),
            None => "::1".parse(),
        }
        .unwrap(),
        locport,
    );
    let buf_source = Arc::new(VecBufSource);

    let mut handles = Vec::new();

    if do_udp {
        let socket = UdpSocket::bind(sockaddr).await.unwrap();

        let config = server::dgram::Config::new();
        let srv = DgramServer::with_config(
            socket,
            buf_source.clone(),
            svc.clone(),
            config,
        );
        let srv = Arc::new(srv);
        handles.push(tokio::spawn(async move { srv.run().await }));
    }

    if do_tcp {
        let listener = TcpListener::bind(sockaddr).await.unwrap();

        let conn_config = server::ConnectionConfig::new();
        let mut config = server::stream::Config::new();
        config.set_connection_config(conn_config);
        let srv =
            StreamServer::with_config(listener, buf_source, svc, config);
        let srv = Arc::new(srv);
        handles.push(tokio::spawn(async move { srv.run().await }));
    }

    handles
}

/// Start a service based on a SingleService, a UDP server socket and a buffer
async fn start_single_service<CR, SVC>(
    svc: SVC,
    server_config: &ServerConfig,
) -> Vec<JoinHandle<()>>
where
    SVC: SingleService<VecU8, CR> + Send + Sync + 'static,
    CR: ComposeReply + Send + Sync + 'static,
{
    let svc = SingleServiceToService::<VecU8, SVC, CR>::new(svc);
    let svc = Arc::new(build_middleware_chain(svc));

    start_service(svc, server_config).await
}

/// Get a socket address for an IP address, and optional port and a
/// default port.
fn get_sockaddr(
    addr: &str,
    port: Option<&str>,
    default_port: u16,
) -> SocketAddr {
    let port = match port {
        Some(str) => str.parse().unwrap(),
        None => default_port,
    };

    SocketAddr::new(IpAddr::from_str(addr).unwrap(), port)
}
