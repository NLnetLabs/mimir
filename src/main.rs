//! Simple DNS proxy

//#![warn(missing_docs)]
//#![warn(clippy::missing_docs_in_private_items)]

use clap::Parser;
use domain::base::iana::Rtype;
use domain::base::message_builder::{AdditionalBuilder, PushError};
use domain::base::opt::{AllOptData, Opt, OptRecord};
use domain::base::wire::Composer;
use domain::base::Name;
use domain::base::{Message, MessageBuilder, ParsedName, StreamTarget};
use domain::dep::octseq::Octets;
use domain::net::client::protocol::{TcpConnect, TlsConnect, UdpConnect};
use domain::net::client::request::{ComposeRequest, RequestMessage, SendRequest};
use domain::net::client::{
    cache, dgram, dgram_stream, load_balancer, multi_stream, redundant, validator,
};
use domain::net::server;
use domain::net::server::adapter::BoxClientTransportToSingleService;
use domain::net::server::adapter::SingleServiceToService;
use domain::net::server::buf::BufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::cookies::CookiesMiddlewareSvc;
use domain::net::server::middleware::edns::EdnsMiddlewareSvc;
use domain::net::server::middleware::mandatory::MandatoryMiddlewareSvc;
use domain::net::server::qname_router::QnameRouter;
use domain::net::server::service::{CallResult, Service, ServiceError, ServiceResult};
use domain::net::server::single_service::ComposeReply;
use domain::net::server::single_service::ReplyMessage;
use domain::net::server::single_service::SingleService;
use domain::net::server::stream::StreamServer;
use domain::rdata::AllRecordData;
use domain::validator::anchor::TrustAnchors;
use domain::validator::context::ValidationContext;
use futures::stream::{once, Once};
use serde::{Deserialize, Serialize};
use serde_aux::field_attributes::bool_true;
use std::fmt::Debug;
use std::fs::File;
use std::future::{ready, Future, Ready};
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::time::Instant;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};

/// Arguments parser.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Option for the local port.
    #[arg(long = "locport", value_parser = clap::value_parser!(u16))]
    locport: Option<u16>,

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
    port: String,
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
    Redundant(CVRedundantConfig),

    /// Load balancer
    #[serde(rename = "lb")]
    LoadBalancer(CVLoadBalancerConfig),

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
    Redundant(CVRedundantConfig),

    /// Load balancer
    #[serde(rename = "lb")]
    LoadBalancer(CVLoadBalancerConfig),

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
}

/// Config for a redundant transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RedundantConfig {
    /// List of upstream configs.
    upstreams: Vec<RedundantUpstreamConfig>,
}

/// Config for a redundant transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CVRedundantConfig {
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
struct CVLoadBalancerConfig {
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

/// Config for a UDP-only transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct UdpConfig {
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

/// Convert a Message into an AdditionalBuilder.
fn to_builder_additional<Octs1: Octets, Target>(
    source: &Message<Octs1>,
) -> Result<AdditionalBuilder<StreamTarget<Target>>, PushError>
where
    Target: Composer + Debug + Default,
    Target::AppendError: Debug,
{
    let mut target =
        MessageBuilder::from_target(StreamTarget::<Target>::new(Default::default()).unwrap())
            .unwrap();

    let header = source.header();
    *target.header_mut() = header;

    let source = source.question();
    let mut target = target.additional().builder().question();
    for rr in source {
        let rr = rr.unwrap();
        target.push(rr)?;
    }
    let mut source = source.answer().unwrap();
    let mut target = target.answer();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let mut source = source.next_section().unwrap().unwrap();
    let mut target = target.authority();
    for rr in &mut source {
        let rr = rr.unwrap();
        let rr = rr
            .into_record::<AllRecordData<_, ParsedName<_>>>()
            .unwrap()
            .unwrap();
        target.push(rr)?;
    }

    let source = source.next_section().unwrap().unwrap();
    let mut target = target.additional();
    for rr in source {
        let rr = rr.unwrap();
        if rr.rtype() == Rtype::OPT {
            let rr = rr.into_record::<Opt<_>>().unwrap().unwrap();
            let opt_record = OptRecord::from_record(rr);
            target
                .opt(|newopt| {
                    newopt.set_udp_payload_size(opt_record.udp_payload_size());
                    newopt.set_version(opt_record.version());
                    newopt.set_dnssec_ok(opt_record.dnssec_ok());

                    // Copy the transitive options that we support.
                    for option in opt_record.opt().iter::<AllOptData<_, _>>() {
                        let option = option.unwrap();
                        if let AllOptData::ExtendedError(_) = option {
                            newopt.push(&option).unwrap();
                        }
                    }
                    Ok(())
                })
                .unwrap();
        } else {
            let rr = rr
                .into_record::<AllRecordData<_, ParsedName<_>>>()
                .unwrap()
                .unwrap();
            target.push(rr)?;
        }
    }

    Ok(target)
}

/// Convert a Message into an AdditionalBuilder with a StreamTarget.
fn to_stream_additional<Octs1: Octets, Target>(
    source: &Message<Octs1>,
) -> Result<AdditionalBuilder<StreamTarget<Target>>, PushError>
where
    Target: Composer + Debug + Default,
    Target::AppendError: Debug,
{
    let builder = to_builder_additional(source).unwrap();
    Ok(builder)
}

struct MyService<RequestOctets, Conn> {
    conn: Conn,

    _phantom: PhantomData<RequestOctets>,
}

impl<RequestOctets, Conn> MyService<RequestOctets, Conn> {
    fn new(conn: Conn) -> Self {
        Self {
            conn,
            _phantom: PhantomData,
        }
    }
}

impl<RequestOctets, Conn> Service<RequestOctets> for MyService<RequestOctets, Conn>
where
    RequestOctets: AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + Unpin + 'static,
    Conn: Clone + SendRequest<RequestMessage<RequestOctets>> + Send + Sync + 'static,
{
    type Target = Vec<u8>;
    type Stream = Once<Ready<ServiceResult<Self::Target>>>;
    type Future = Pin<Box<dyn Future<Output = Self::Stream> + Send>>;

    fn call(&self, request: Request<RequestOctets>) -> Self::Future {
        let conn = self.conn.clone();
        let fut = async move {
            let now = Instant::now();
            let msg: Message<RequestOctets> = request.message().as_ref().clone();

            // The middleware layer will take care of the ID in the reply.

            // We get a Message, but the client transport needs a ComposeRequest
            // (which is implemented by RequestMessage). Convert.

            let do_bit = dnssec_ok(&msg);
            // We get a Message, but the client transport needs a
            // BaseMessageBuilder. Convert.
            println!("request {:?}", msg);
            let mut request_msg = RequestMessage::new(msg).unwrap();
            println!("request {:?}", request_msg);
            // Set the DO bit if it is set in the request.
            if do_bit {
                request_msg.set_dnssec_ok(true);
            }

            let mut query = conn.send_request(request_msg);
            let reply = query.get_response().await.unwrap();
            println!("query_service: response after {:?}", now.elapsed());
            println!("got reply {:?}", reply);

            // We get the reply as Message from the client transport but
            // we need to return an AdditionalBuilder with a StreamTarget. Convert.
            let stream = to_stream_additional::<_, _>(&reply).unwrap();
            once(ready(Ok(CallResult::new(stream))))
        };
        Box::pin(fut)
    }
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

/// A single optional call result based on a Vector.
struct VecSingle(Option<CallResult<Vec<u8>>>);

impl Future for VecSingle {
    type Output = Result<CallResult<Vec<u8>>, ServiceError>;

    fn poll(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(self.0.take().unwrap()))
    }
}

/// Vector of octets
type VecU8 = Vec<u8>;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let f = File::open(args.config).unwrap();
    let conf: Config = serde_json::from_reader(f).unwrap();

    println!("Got: {:?}", conf);

    let toml = toml::to_string(&conf).unwrap();

    println!("Got toml:\n{toml}");

    let locport = args.locport.unwrap_or_else(|| "8053".parse().unwrap());
    let buf_source = Arc::new(VecBufSource);
    let udpsocket2 = UdpSocket::bind(SocketAddr::new("::1".parse().unwrap(), locport))
        .await
        .unwrap();
    let tcplistener = TcpListener::bind(SocketAddr::new("::1".parse().unwrap(), locport))
        .await
        .unwrap();

    // We cannot use get_transport because we cannot pass a Box<dyn ...> to
    // query_service because it lacks Clone.
    let udp_join_handle = match conf.upstream {
        TopUpstreamConfig::Qname(qname_conf) => {
            let qr = get_qname_router::<ReplyMessage>(qname_conf).await;
            start_single_service(qr, udpsocket2, tcplistener, buf_source)
        }
        TopUpstreamConfig::Redundant(redun_conf) => {
            let redun = get_cvredun(&redun_conf).await;
            start_cache_validator_service(
                redun_conf.cache,
                redun_conf.validator,
                redun,
                udpsocket2,
                tcplistener,
                buf_source,
            )
        }
        TopUpstreamConfig::LoadBalancer(lb_conf) => {
            let redun = get_cvlb(&lb_conf).await;
            start_cache_validator_service(
                lb_conf.cache,
                lb_conf.validator,
                redun,
                udpsocket2,
                tcplistener,
                buf_source,
            )
        }
        TopUpstreamConfig::Tcp(tcp_conf) => {
            let tcp = get_tcp::<RequestMessage<VecU8>>(&tcp_conf);
            start_service(tcp, udpsocket2, tcplistener, buf_source)
        }
        TopUpstreamConfig::Tls(tls_conf) => {
            let tls = get_tls::<RequestMessage<VecU8>>(&tls_conf);
            start_service(tls, udpsocket2, tcplistener, buf_source)
        }
        TopUpstreamConfig::Udp(udp_conf) => {
            let udp = get_udp::<RequestMessage<VecU8>>(&udp_conf);
            start_service(udp, udpsocket2, tcplistener, buf_source)
        }
        TopUpstreamConfig::UdpTcp(udptcp_conf) => {
            let udptcp = get_udptcp::<RequestMessage<VecU8>>(&udptcp_conf);
            start_service(udptcp, udpsocket2, tcplistener, buf_source)
        }
    };

    udp_join_handle.await.unwrap();
}

/// Get a qname router based on its config
async fn get_qname_router<CR>(config: QnameConfig) -> QnameRouter<Vec<u8>, VecU8, CR>
where
    CR: ComposeReply + Send + Sync + 'static,
{
    println!("Creating new QnameRouter");
    let mut qr = QnameRouter::new();
    println!("Adding to QnameRouter");
    for e in config.domains {
        println!("Add to QnameRouter");
        let transp = get_qr_transport(&e.upstream, &e.cache, &e.validator).await;
        let svc = BoxClientTransportToSingleService::new(transp);
        qr.add(Name::<Vec<u8>>::from_str(&e.name).unwrap(), svc);
        println!("After Add to QnameRouter");
    }
    qr
}

/// Get a redundant transport based on its config
async fn get_redun(config: &RedundantConfig) -> redundant::Connection<RequestMessage<VecU8>> {
    println!("Creating new redundant::Connection");
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to redundant::Connection");
    for e in &config.upstreams {
        println!("Add to redundant::Connection");
        redun.add(get_simple_transport(&e.upstream)).await.unwrap();
        println!("After Add to redundant::Connection");
    }
    redun
}

/// Get a redundant transport based on its config
async fn get_cvredun(config: &CVRedundantConfig) -> redundant::Connection<RequestMessage<VecU8>> {
    println!("Creating new redundant::Connection");
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to redundant::Connection");
    for e in &config.upstreams {
        println!("Add to redundant::Connection");
        redun.add(get_simple_transport(&e.upstream)).await.unwrap();
        println!("After Add to redundant::Connection");
    }
    redun
}

/// Get a load balanced transport based on its config
async fn get_lb(config: &LoadBalancerConfig) -> load_balancer::Connection<RequestMessage<VecU8>> {
    println!("Creating new load_balancer::Connection");
    let (lb, transport) = load_balancer::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to load_balancer::Connection");
    for e in &config.upstreams {
        println!("Add to load_balancer::Connection");
        let mut conf = load_balancer::ConnConfig::new();
        conf.set_max_burst(e.max_burst);
        if let Some(f) = e.burst_interval {
            conf.set_burst_interval(Duration::from_secs_f64(f));
        }
        lb.add(&e.label, &conf, get_simple_transport(&e.upstream))
            .await
            .unwrap();
        println!("After Add to load_balancer::Connection");
    }
    let lb2 = lb.clone();
    tokio::spawn(async move {
        loop {
            lb2.print_stats().await;
            sleep(Duration::from_secs(60)).await;
        }
    });
    lb
}

/// Get a load balanced transport based on its config
async fn get_cvlb(
    config: &CVLoadBalancerConfig,
) -> load_balancer::Connection<RequestMessage<VecU8>> {
    println!("Creating new load_balancer::Connection");
    let (lb, transport) = load_balancer::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to load_balancer::Connection");
    for e in &config.upstreams {
        println!("Add to load_balancer::Connection");
        let mut conf = load_balancer::ConnConfig::new();
        conf.set_max_burst(e.max_burst);
        if let Some(f) = e.burst_interval {
            conf.set_burst_interval(Duration::from_secs_f64(f));
        }
        lb.add(&e.label, &conf, get_simple_transport(&e.upstream))
            .await
            .unwrap();
        println!("After Add to load_balancer::Connection");
    }
    let lb2 = lb.clone();
    tokio::spawn(async move {
        loop {
            lb2.print_stats().await;
            sleep(Duration::from_secs(60)).await;
        }
    });
    lb
}

/// Get a TCP transport based on its config
fn get_tcp<CR: ComposeRequest + Clone + 'static>(
    config: &TcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);
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
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 853);

    // Some TLS boiler plate for the root certificates.
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let client_config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let tls_connect = TlsConnect::new(
        client_config,
        String::from(config.servername.as_str()).try_into().unwrap(),
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
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);

    let udp_connect = UdpConnect::new(sockaddr);
    dgram::Connection::new(udp_connect)
}

/// Get a UDP+TCP transport based on its config
fn get_udptcp<CR: ComposeRequest + Clone + Debug + 'static>(
    config: &UdpTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);
    let udp_connect = UdpConnect::new(sockaddr);
    let tcp_connect = TcpConnect::new(sockaddr);
    let (conn, transport) = dgram_stream::Connection::new(udp_connect, tcp_connect);
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
    let a: Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> = match config {
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
    let a: Box<dyn SendRequest<RequestMessage<VecU8>> + Send + Sync> = match config {
        TransportConfig::Tcp(tcp_conf) => Box::new(get_tcp(&tcp_conf)),
        TransportConfig::Tls(tls_conf) => Box::new(get_tls(&tls_conf)),
        TransportConfig::Udp(udp_conf) => Box::new(get_udp(&udp_conf)),
        TransportConfig::UdpTcp(udptcp_conf) => Box::new(get_udptcp(&udptcp_conf)),
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
                let anchor_file = File::open("root.key").unwrap();
                let ta = TrustAnchors::from_reader(anchor_file).unwrap();
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

fn start_cache_validator_service(
    cache_conf: Option<CacheConfig>,
    validator_conf: Option<ValidatorConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    socket: UdpSocket,
    listener: TcpListener,
    buf_source: Arc<VecBufSource>,
) -> JoinHandle<()> {
    match validator_conf {
        Some(validator_conf) => {
            if validator_conf.enabled {
                let anchor_file = File::open("root.key").unwrap();
                let ta = TrustAnchors::from_reader(anchor_file).unwrap();
                let vc = Arc::new(ValidationContext::new(ta, conn.clone()));
                let conn = validator::Connection::new(conn, vc);
                start_cache_service(cache_conf, conn, socket, listener, buf_source)
            } else {
                start_cache_service(cache_conf, conn, socket, listener, buf_source)
            }
        }
        None => start_cache_service(cache_conf, conn, socket, listener, buf_source),
    }
}

fn start_cache_service(
    cache_conf: Option<CacheConfig>,
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    socket: UdpSocket,
    listener: TcpListener,
    buf_source: Arc<VecBufSource>,
) -> JoinHandle<()> {
    match cache_conf {
        Some(cache_conf) => {
            if cache_conf.enabled {
                let conn = cache::Connection::new(conn);
                start_service(conn, socket, listener, buf_source)
            } else {
                start_service(conn, socket, listener, buf_source)
            }
        }
        None => start_service(conn, socket, listener, buf_source),
    }
}

/// Start a service based on a transport, a UDP server socket and a buffer
fn start_service(
    conn: impl SendRequest<RequestMessage<VecU8>> + Clone + Send + Sync + 'static,
    socket: UdpSocket,
    listener: TcpListener,
    buf_source: Arc<VecBufSource>,
) -> JoinHandle<()>
where
{
    let svc = MyService::new(conn);
    let svc = Arc::new(build_middleware_chain(svc));
    let config = server::dgram::Config::new();
    let srv = DgramServer::with_config(socket, buf_source.clone(), svc.clone(), config);
    let srv = Arc::new(srv);
    tokio::spawn(async move { srv.run().await });

    let conn_config = server::ConnectionConfig::new();
    let mut config = server::stream::Config::new();
    config.set_connection_config(conn_config);
    let srv = StreamServer::with_config(listener, buf_source, svc, config);
    let srv = Arc::new(srv);
    tokio::spawn(async move { srv.run().await })
}

/// Start a service based on a SingleService, a UDP server socket and a buffer
fn start_single_service<CR, SVC>(
    svc: SVC,
    socket: UdpSocket,
    listener: TcpListener,
    buf_source: Arc<VecBufSource>,
) -> JoinHandle<()>
where
    SVC: SingleService<VecU8, CR> + Send + Sync + 'static,
    CR: ComposeReply + Send + Sync + 'static,
{
    let svc = SingleServiceToService::<VecU8, SVC, CR>::new(svc);
    let svc = Arc::new(build_middleware_chain(svc));
    let config = server::dgram::Config::new();
    let srv = DgramServer::with_config(socket, buf_source.clone(), svc.clone(), config);
    let srv = Arc::new(srv);
    tokio::spawn(async move { srv.run().await });

    let conn_config = server::ConnectionConfig::new();
    let mut config = server::stream::Config::new();
    config.set_connection_config(conn_config);
    let srv = StreamServer::with_config(listener, buf_source, svc, config);
    let srv = Arc::new(srv);
    tokio::spawn(async move { srv.run().await })
}

/// Get a socket address for an IP address, and optional port and a
/// default port.
fn get_sockaddr(addr: &str, port: Option<&str>, default_port: u16) -> SocketAddr {
    let port = match port {
        Some(str) => str.parse().unwrap(),
        None => default_port,
    };

    SocketAddr::new(IpAddr::from_str(addr).unwrap(), port)
}

/// Return whether the DO flag is set.
fn dnssec_ok<Octs: Octets>(msg: &Message<Octs>) -> bool {
    if let Some(opt) = msg.opt() {
        opt.dnssec_ok()
    } else {
        false
    }
}
