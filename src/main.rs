//! Simple DNS proxy

#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

use crate::server::service::Transaction;
use clap::Parser;
use domain::base::iana::Rtype;
use domain::base::message_builder::{AdditionalBuilder, PushError};
use domain::base::opt::{Opt, OptRecord};
use domain::base::opt::AllOptData;
use domain::base::wire::Composer;
use domain::base::{Message, MessageBuilder, ParsedName, StreamTarget};
use domain::dep::octseq::Octets;
use domain::dep::octseq::OctetsBuilder;
use domain::net::client::cache;
use domain::net::client::dgram;
use domain::net::client::dgram_stream;
use domain::net::client::multi_stream;
use domain::net::client::protocol::TlsConnect;
use domain::net::client::protocol::{TcpConnect, UdpConnect};
use domain::net::client::redundant;
use domain::net::client::request::SendRequest;
use domain::net::client::request::{ComposeRequest, RequestMessage};
use domain::net::client::validator;
use domain::net::server;
use domain::net::server::buf::BufSource;
use domain::net::server::dgram::DgramServer;
use domain::net::server::message::Request;
use domain::net::server::middleware::builder::MiddlewareBuilder;
use domain::net::server::service::{CallResult, Service, ServiceError};
use domain::net::server::stream::StreamServer;
use domain::net::server::util::service_fn;
use domain::validator::anchor::TrustAnchors;
use domain::validator::context::ValidationContext;
use domain::rdata::AllRecordData;
use futures_util::{future::BoxFuture, FutureExt};
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use serde::Deserialize;
use serde::Serialize;
use std::fmt::Debug;
use std::fs::File;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

/// Select whether to use service_fn or not.
const USE_MK_SERVICE: bool = false;

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
    /// Config for upstream connections
    upstream: TransportConfig,
}

/// Configure for client transports
#[derive(Clone, Debug, Deserialize, Serialize)]
enum TransportConfig {
    /// Cached upstreams
    #[serde(rename = "cache")]
    Cache(CacheConfig),

    /// Validated upstreams
    #[serde(rename = "validated")]
    Validated(ValidatedConfig),

    /// Redudant upstreams
    #[serde(rename = "redundant")]
    Redundant(RedundantConfig),

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

/// Config for a cached transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheConfig {
    /// upstream transport
    upstream: Box<TransportConfig>,
}

/// Config for a validated transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct ValidatedConfig {
    /// upstream transport
    upstream: Box<TransportConfig>,
}

/// Config for a redundant transport
#[derive(Clone, Debug, Deserialize, Serialize)]
struct RedundantConfig {
    /// List of transports to be used by a redundant transport
    transports: Vec<TransportConfig>,
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
    let mut target = MessageBuilder::from_target(
        StreamTarget::<Target>::new(Default::default()).unwrap(),
    )
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
                    newopt
                        .set_udp_payload_size(opt_record.udp_payload_size());
                    newopt.set_version(opt_record.version());
                    newopt.set_dnssec_ok(opt_record.dnssec_ok());

                    // Copy the transitive options that we support. 
		    for option in opt_record.opt().iter::<AllOptData<_, _>>()
		    {
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

/// Function that returns a Service trait.
///
/// This is a trick to capture the Future by an async block into a type.
fn query_service<RequestOctets, Target>(
    conn: impl SendRequest<RequestMessage<RequestOctets>>
        + Clone
        + Send
        + Sync
        + 'static,
) -> impl Service<RequestOctets, Target = Target,
	Future = impl Future<Output = Result<CallResult<Target>, ServiceError>> + Send>
where
    RequestOctets:
        AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static,
    for<'a> &'a RequestOctets: AsRef<[u8]> + Debug,
    Target: AsMut<[u8]>
        + AsRef<[u8]>
        + Composer
        + Debug
        + Default
        + OctetsBuilder
        + Send
        + Sync
        + 'static,
    Target::AppendError: Debug,
{
    /// Basic query function for Service.
    fn query<RequestOctets, Target>(
        ctxmsg: Request<RequestOctets>,
        conn: impl SendRequest<RequestMessage<RequestOctets>> + Send + Sync,
    ) -> Result<
        Transaction<
            Target,
            impl Future<Output = Result<CallResult<Target>, ServiceError>> + Send,
        >,
        ServiceError,
    >
    where
        RequestOctets:
            AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static,
        for<'a> &'a RequestOctets: AsRef<[u8]> + Debug,
        Target: AsMut<[u8]>
            + AsRef<[u8]>
            + Composer
            + Debug
            + Default
            + OctetsBuilder
	    + Send,
        Target::AppendError: Debug,
    {
        Ok(Transaction::single(async move {
	    let now = Instant::now();
            let msg: Message<RequestOctets> =
                ctxmsg.message().as_ref().clone();

            // The middleware layer will take care of the ID in the reply.

            // We get a Message, but the client transport needs a ComposeRequest
            // (which is implemented by RequestMessage). Convert.

            let do_bit = dnssec_ok(&msg);
            // We get a Message, but the client transport needs a
            // BaseMessageBuilder. Convert.
            println!("request {:?}", msg);
            let mut request_msg = RequestMessage::new(msg);
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
            Ok(CallResult::new(stream))
        }))
    }

    move |message| query::<RequestOctets, Target>(message, conn.clone())
}

/// Query function for service_fn.
fn do_query<RequestOctets, Target, Metadata>(
    ctxmsg: Request<RequestOctets>,
    conn: Metadata,
) -> Result<
    Transaction<
        Target,
        impl Future<Output = Result<CallResult<Target>, ServiceError>> + Send,
    >,
    ServiceError,
>
where
    RequestOctets:
        AsRef<[u8]> + Clone + Debug + Octets + Send + Sync + 'static,
    Target: AsMut<[u8]>
        + AsRef<[u8]>
        + Composer
        + Debug
        + Default
        + OctetsBuilder,
    Target::AppendError: Debug,
    Metadata: SendRequest<RequestMessage<RequestOctets>> + Send + 'static,
{
    Ok(Transaction::single(Box::pin(async move {
        let msg: Message<RequestOctets> = ctxmsg.message().as_ref().clone();

        // The middleware layer will take care of the ID in the reply.

        // We get a Message, but the client transport needs a ComposeRequest
        // (which is implemented by RequestMessage). Convert.

        let do_bit = dnssec_ok(&msg);
        // We get a Message, but the client transport needs a
        // BaseMessageBuilder. Convert.
        println!("request {:?}", msg);
        let mut request_msg = RequestMessage::new(msg);
        println!("request {:?}", request_msg);
        // Set the DO bit if it is set in the request.
        if do_bit {
            request_msg.set_dnssec_ok(true);
        }

        let mut query = conn.send_request(request_msg);
        let reply = query.get_response().await.unwrap();
        println!("got reply {:?}", reply);

        // We get the reply as Message from the client transport but
        // we need to return an AdditionalBuilder with a StreamTarget. Convert.
        let stream = to_stream_additional::<_, _>(&reply).unwrap();
        Ok(CallResult::new(stream))
    })))
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

    fn poll(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
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

    let locport = args.locport.unwrap_or_else(|| "8053".parse().unwrap());
    let buf_source = Arc::new(VecBufSource);
    let udpsocket2 =
        UdpSocket::bind(SocketAddr::new("::1".parse().unwrap(), locport))
            .await
            .unwrap();
    let tcplistener =
        TcpListener::bind(SocketAddr::new("::1".parse().unwrap(), locport))
            .await
            .unwrap();

    // We cannot use get_transport because we cannot pass a Box<dyn ...> to
    // query_service because it lacks Clone.
    let udp_join_handle = match conf.upstream {
        TransportConfig::Cache(cache_conf) => {
            // We cannot call get_transport here, because we need cache to
            // match the type of upstream. Would an enum help here?
            println!("cache_conf: {cache_conf:?}");
            match &*cache_conf.upstream {
                TransportConfig::Cache(_cache_conf) => {
                    panic!("Nested caches are not possible");
                }
                TransportConfig::Validated(validated_conf) => {
		    // We cannot call get_transport here, because we need
		    // validator to match the type of upstream.
		    println!("validated_conf: {validated_conf:?}");
		    let anchor_file = File::open("root.key").unwrap();
		    let ta = TrustAnchors::from_reader(anchor_file).unwrap();
		    match &*validated_conf.upstream {
			TransportConfig::Redundant(redun_conf) => {
			    let upstream = get_redun(redun_conf.clone()).await;
			    let vc = Arc::new(ValidationContext::new(ta, upstream.clone()));
			    let validated = get_validated(validated_conf.clone(),
				upstream, vc).await;
			    let cache = get_cache(cache_conf, validated).await;
			    start_service(cache, udpsocket2, tcplistener, buf_source)
			}
			_ => todo!()
		    }
		}
                TransportConfig::Tcp(tcp_conf) => {
                    let upstream = get_tcp(tcp_conf.clone());
                    let cache = get_cache(cache_conf, upstream).await;
                    start_service(cache, udpsocket2, tcplistener, buf_source)
                }
                TransportConfig::Tls(tls_conf) => {
                    let upstream = get_tls(tls_conf.clone());
                    let cache = get_cache(cache_conf, upstream).await;
                    start_service(cache, udpsocket2, tcplistener, buf_source)
                }
                TransportConfig::Redundant(redun_conf) => {
                    let upstream = get_redun(redun_conf.clone()).await;
                    let cache = get_cache(cache_conf, upstream).await;
                    start_service(cache, udpsocket2, tcplistener, buf_source)
                }
                TransportConfig::Udp(udp_conf) => {
                    let upstream = get_udp(udp_conf.clone());
                    let cache = get_cache(cache_conf, upstream).await;
                    start_service(cache, udpsocket2, tcplistener, buf_source)
                }
                TransportConfig::UdpTcp(udptcp_conf) => {
                    let upstream = get_udptcp(udptcp_conf.clone());
                    let cache = get_cache(cache_conf, upstream).await;
                    start_service(cache, udpsocket2, tcplistener, buf_source)
                }
            }
        }
        TransportConfig::Validated(_) => todo!(),
        TransportConfig::Redundant(redun_conf) => {
            let redun = get_redun::<RequestMessage<VecU8>>(redun_conf).await;
            start_service(redun, udpsocket2, tcplistener, buf_source)
        }
        TransportConfig::Tcp(tcp_conf) => {
            let tcp = get_tcp::<RequestMessage<VecU8>>(tcp_conf);
            start_service(tcp, udpsocket2, tcplistener, buf_source)
        }
        TransportConfig::Tls(tls_conf) => {
            let tls = get_tls::<RequestMessage<VecU8>>(tls_conf);
            start_service(tls, udpsocket2, tcplistener, buf_source)
        }
        TransportConfig::Udp(udp_conf) => {
            let udp = get_udp::<RequestMessage<VecU8>>(udp_conf);
            start_service(udp, udpsocket2, tcplistener, buf_source)
        }
        TransportConfig::UdpTcp(udptcp_conf) => {
            let udptcp = get_udptcp::<RequestMessage<VecU8>>(udptcp_conf);
            start_service(udptcp, udpsocket2, tcplistener, buf_source)
        }
    };

    udp_join_handle.await.unwrap();
}

/// Get a cached transport based on its config
async fn get_cache<Upstream>(
    _config: CacheConfig,
    upstream: Upstream,
) -> cache::Connection<Upstream> {
    println!("Create new cache");
    cache::Connection::new(upstream)
}

/// Get a validated transport based on its config
async fn get_validated<Upstream, VCOcts, VCUpstream>(
    _config: ValidatedConfig,
    upstream: Upstream,
    vcupstream: Arc<ValidationContext<VCUpstream>>,
) -> validator::Connection<Upstream, VCOcts, VCUpstream> {
    println!("Create new validated");
    validator::Connection::new(upstream, vcupstream)
}

/// Get a redundant transport based on its config
async fn get_redun<
    CR: ComposeRequest + Clone + Debug + Send + Sync + 'static,
>(
    config: RedundantConfig,
) -> redundant::Connection<CR> {
    println!("Creating new redundant::Connection");
    let (redun, transport) = redundant::Connection::new();
    tokio::spawn(async move {
        transport.run().await;
    });
    println!("Adding to redundant::Connection");
    for e in config.transports {
        println!("Add to redundant::Connection");
        redun.add(get_transport(e).await).await.unwrap();
        println!("After Add to redundant::Connection");
    }
    redun
}

/// Get a TCP transport based on its config
fn get_tcp<CR: ComposeRequest + Clone + 'static>(
    config: TcpConfig,
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
    config: TlsConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 853);

    // Some TLS boiler plate for the root certificates.
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };

    let client_config = 
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    ;

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
    config: UdpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);

    let udp_connect = UdpConnect::new(sockaddr);
    dgram::Connection::new(udp_connect)
}

/// Get a UDP+TCP transport based on its config
fn get_udptcp<CR: ComposeRequest + Clone + Debug + 'static>(
    config: UdpTcpConfig,
) -> impl SendRequest<CR> + Clone + Send + Sync {
    let sockaddr = get_sockaddr(&config.addr, config.port.as_deref(), 53);
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
fn get_transport<CR: ComposeRequest + Clone + 'static>(
    config: TransportConfig,
) -> BoxFuture<'static, Box<dyn SendRequest<CR> + Send + Sync>> {
    // We have an indirectly recursive async function. This function calls
    // get_redun which calls this function. The solution is to return a
    // boxed future.
    async move {
        println!("got config {:?}", config);
        let a: Box<dyn SendRequest<CR> + Send + Sync> = match config {
            TransportConfig::Cache(cache_conf) => {
                println!("cache_conf: {cache_conf:?}");
                match &*cache_conf.upstream {
                    TransportConfig::Cache(_) => {
                        panic!("Nested caches are not possible");
                    }
                    TransportConfig::Validated(_) => todo!(),
                    TransportConfig::Redundant(redun_conf) => {
                        let upstream = get_redun(redun_conf.clone()).await;
                        let cache = get_cache(cache_conf, upstream).await;
                        Box::new(cache)
                    }
                    TransportConfig::Tcp(tcp_conf) => {
                        let upstream = get_tcp(tcp_conf.clone());
                        let cache = get_cache(cache_conf, upstream).await;
                        Box::new(cache)
                    }
                    TransportConfig::Tls(tls_conf) => {
                        let upstream = get_tls(tls_conf.clone());
                        let cache = get_cache(cache_conf, upstream).await;
                        Box::new(cache)
                    }
                    TransportConfig::Udp(udp_conf) => {
                        let upstream = get_udp(udp_conf.clone());
                        let cache = get_cache(cache_conf, upstream).await;
                        Box::new(cache)
                    }
                    TransportConfig::UdpTcp(udptcp_conf) => {
                        let upstream = get_udptcp(udptcp_conf.clone());
                        let cache = get_cache(cache_conf, upstream).await;
                        Box::new(cache)
                    }
                }
            }
            TransportConfig::Validated(_) => todo!(),
            TransportConfig::Redundant(redun_conf) => {
                Box::new(get_redun(redun_conf).await)
            }
            TransportConfig::Tcp(tcp_conf) => Box::new(get_tcp(tcp_conf)),
            TransportConfig::Tls(tls_conf) => Box::new(get_tls(tls_conf)),
            TransportConfig::Udp(udp_conf) => Box::new(get_udp(udp_conf)),
            TransportConfig::UdpTcp(udptcp_conf) => {
                Box::new(get_udptcp(udptcp_conf))
            }
        };
        a
    }
    .boxed()
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
    if USE_MK_SERVICE {
        let svc = service_fn::<VecU8, VecU8, _, _, _>(do_query, conn);
        let mw = MiddlewareBuilder::default().build();
        let mut config = server::dgram::Config::new();
        config.set_middleware_chain(mw);
        let srv = DgramServer::with_config(
            socket,
            buf_source,
            Arc::new(svc),
            config,
        );
        let srv = Arc::new(srv);
        tokio::spawn(async move { srv.run().await })

	
    } else {
        let svc = query_service::<VecU8, VecU8>(conn);
	let svc = Arc::new(svc);
        let mw = MiddlewareBuilder::default().build();
        let mut config = server::dgram::Config::new();
        config.set_middleware_chain(mw.clone());
        let srv = DgramServer::with_config(
            socket,
            buf_source.clone(),
            svc.clone(),
            config,
        );
        let srv = Arc::new(srv);
        tokio::spawn(async move { srv.run().await });

	let mut conn_config = server::ConnectionConfig::new();
        conn_config.set_middleware_chain(mw);
        let mut config = server::stream::Config::new();
	config.set_connection_config(conn_config);
	let srv = StreamServer::with_config(listener,
	    buf_source,
	    svc,
	    config);
	let srv = Arc::new(srv);
        tokio::spawn(async move { srv.run().await })
    }
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

/// Return whether the DO flag is set.
fn dnssec_ok<Octs: Octets>(msg: &Message<Octs>) -> bool {
    if let Some(opt) = msg.opt() {
        opt.dnssec_ok()
    } else {
        false
    }
}
