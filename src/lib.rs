use std::net::{SocketAddr, IpAddr};
use anyhow::{Result, Context};
use tokio::net::{UdpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use reqwest::{Client, Url};
use std::sync::{Arc, Mutex};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, error, debug}; // Add tracing import

use std::time::Duration;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::{VecDeque, HashMap};
use std::sync::LazyLock;
use bytes::Bytes;
use moka::future::Cache;
use odoh_rs::{ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHMessage, ObliviousDoHMessagePlaintext, ObliviousDoHConfigContents, encrypt_query, decrypt_response, parse, compose}; // Corrected odoh_rs imports, added compose
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::io::Cursor; // For parsing

pub struct Stats {
    pub queries_udp: AtomicUsize,
    pub queries_tcp: AtomicUsize,
    pub errors: AtomicUsize,
}

struct LogMessage {
    domain: String,
    status: String,
}

static QUERY_LOGS: LazyLock<Mutex<VecDeque<String>>> = LazyLock::new(|| Mutex::new(VecDeque::with_capacity(50)));
static LOG_SENDER: LazyLock<mpsc::UnboundedSender<LogMessage>> = LazyLock::new(|| {
    let (tx, mut rx) = mpsc::unbounded_channel::<LogMessage>();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let mut logs = QUERY_LOGS.lock().unwrap();
            if logs.len() >= 50 {
                logs.pop_front();
            }
            let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
            logs.push_back(format!("[{}] {} -> {}", timestamp, msg.domain, msg.status));
        }
    });
    tx
});

#[cfg(feature = "jni")]
static GLOBAL_STATS: LazyLock<RwLock<Option<Arc<Stats>>>> = LazyLock::new(|| RwLock::new(None));
#[cfg(feature = "jni")]
static GLOBAL_CACHE: LazyLock<RwLock<Option<DnsCache>>> = LazyLock::new(|| RwLock::new(None));

static LAST_LATENCY: AtomicUsize = AtomicUsize::new(0);

fn add_query_log(domain: String, status: String) {
    debug!("QUERY: {} -> {}", domain, status);
    let _ = LOG_SENDER.send(LogMessage { domain, status });
}

impl Stats {
    pub fn new() -> Self {
        Self {
            queries_udp: AtomicUsize::new(0),
            queries_tcp: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Config {
    pub listen_addr: String,
    pub listen_port: u16,
    pub tcp_client_limit: usize,
    pub bootstrap_dns: String,
    pub polling_interval: u64,
    pub force_ipv4: bool,
    pub allow_ipv6: bool,
    pub resolver_url: String, // ODoH Target URL
    pub proxy_server: Option<String>,
    pub source_addr: Option<String>,
    pub http11: bool,
    pub http3: bool,
    pub max_idle_time: u64,
    pub conn_loss_time: u64,
    pub ca_path: Option<String>,
    pub statistic_interval: u64,
    pub cache_ttl: u64,
}

type DnsCache = Cache<Bytes, (Bytes, u32)>;

#[derive(Clone)]
struct DynamicResolver {
    hosts: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
}

impl DynamicResolver {
    fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn update(&self, domain: String, addr: SocketAddr) {
        let mut hosts = self.hosts.write().await;
        hosts.insert(domain, vec![addr]);
    }
}

use reqwest::dns::{Resolve, Resolving, Name, Addrs};
impl Resolve for DynamicResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let name_str = name.as_str().to_string();
        let hosts = self.hosts.clone();
        Box::pin(async move {
            let hosts = hosts.read().await;
            if let Some(addrs) = hosts.get(&name_str) {
                Ok(Box::new(addrs.clone().into_iter()) as Addrs)
            } else {
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "Host not found")) as Box<dyn std::error::Error + Send + Sync>)
            }
        })
    }
}

// Global ODoH Config Cache
static ODOH_CONFIG: LazyLock<RwLock<Option<ObliviousDoHConfig>>> = LazyLock::new(|| RwLock::new(None));

pub async fn run_proxy(config: Config, stats: Arc<Stats>, mut shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
        .parse()
        .context("Failed to parse listen address")?;

    let resolver_url_parsed = Url::parse(&config.resolver_url)
        .context("Failed to parse resolver URL")?;
    let resolver_domain = resolver_url_parsed.domain().context("Resolver URL must have a domain")?.to_string();

    let mut udp_socket = None;
    let mut tcp_listener = None;
    for i in 0..5 {
        match UdpSocket::bind(addr).await {
            Ok(s) => {
                match TcpListener::bind(addr).await {
                    Ok(l) => {
                        udp_socket = Some(Arc::new(s));
                        tcp_listener = Some(l);
                        break;
                    }
                    Err(e) => { error!("Failed to bind TCP ({}): {}", i, e); }
                }
            }
            Err(e) => { error!("Failed to bind UDP ({}): {}", i, e); }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let udp_socket = udp_socket.context("Failed to bind UDP")?;
    let tcp_listener = tcp_listener.context("Failed to bind TCP")?;

    info!("Listening on {} -> ODoH Target {}", addr, config.resolver_url);

    let ip = resolve_bootstrap(&resolver_domain, &config.bootstrap_dns, config.allow_ipv6).await?;
    info!("Bootstrapped {} to {}", resolver_domain, ip);
    
    let dynamic_resolver = DynamicResolver::new();
    dynamic_resolver.update(resolver_domain.clone(), ip).await;

    let client = create_client(&config, Arc::new(dynamic_resolver))?;
    
    // Fetch ODoH Config
    match fetch_odoh_config(&client, &config.resolver_url).await {
        Ok(c) => {
            let mut w = ODOH_CONFIG.write().await;
            *w = Some(c);
            info!("Fetched ODoH Config successfully");
        }
        Err(e) => {
            error!("Failed to fetch ODoH Config: {}", e);
        }
    }

    let resolver_url_str = Arc::new(config.resolver_url.clone());
    let cache: DnsCache = Cache::builder().max_capacity(2048).build();

    #[cfg(feature = "jni")]
    {
        let mut w = GLOBAL_CACHE.write().await;
        *w = Some(cache.clone());
    }

    let udp_loop = {
        let socket = udp_socket.clone();
        let client = client.clone();
        let resolver_url = resolver_url_str.clone();
        let stats = stats.clone();
        let cache = cache.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let data = Bytes::copy_from_slice(&buf[..len]);
                        let socket = socket.clone();
                        let client = client.clone();
                        let resolver_url = resolver_url.clone();
                        let stats = stats.clone();
                        let cache = cache.clone();
                        tokio::spawn(async move {
                            stats.queries_udp.fetch_add(1, Ordering::Relaxed);
                            if let Err(e) = handle_query(Some(socket), None, client, resolver_url, data, peer, stats, cache).await {
                                debug!("UDP error: {}", e);
                            }
                        });
                    }
                    Err(_) => break,
                }
            }
        })
    };

    let tcp_loop = {
         let listener = tcp_listener;
         let client = client.clone();
         let resolver_url = resolver_url_str.clone();
         let stats = stats.clone();
         let cache = cache.clone();
         tokio::spawn(async move {
            loop {
                if let Ok((mut stream, peer)) = listener.accept().await {
                     let client = client.clone();
                     let resolver_url = resolver_url.clone();
                     let stats = stats.clone();
                     let cache = cache.clone();
                     tokio::spawn(async move {
                         stats.queries_tcp.fetch_add(1, Ordering::Relaxed);
                         let mut len_buf = [0u8; 2];
                         if stream.read_exact(&mut len_buf).await.is_ok() {
                             let len = u16::from_be_bytes(len_buf) as usize;
                             let mut data = vec![0u8; len];
                             if stream.read_exact(&mut data).await.is_ok() {
                                 let _ = handle_query(None, Some(stream), client, resolver_url, Bytes::from(data), peer, stats, cache).await;
                             }
                         }
                     });
                }
            }
         })
    };

    tokio::select! {
        _ = &mut shutdown_rx => info!("Shutting down..."),
        _ = udp_loop => {},
        _ = tcp_loop => {},
    }
    Ok(())
}

async fn fetch_odoh_config(client: &Client, target_url: &str) -> Result<ObliviousDoHConfig> {
    let config_url = if target_url.ends_with('/') {
        format!("{}.well-known/odohconfigs", target_url)
    } else {
        format!("{}/.well-known/odohconfigs", target_url)
    };

    let resp = client.get(&config_url).send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("Failed to get odohconfigs: {}", resp.status()));
    }
    let bytes = resp.bytes().await?;
    
    let mut cursor = Cursor::new(bytes); // Use Cursor for parsing
    let configs: ObliviousDoHConfigs = parse(&mut cursor)?; // Parse into ObliviousDoHConfigs
    let config = configs.supported().into_iter().next().ok_or_else(|| anyhow::anyhow!("No supported ODoH config found"))?;
    Ok(config)
}

async fn handle_query(
    udp_sock: Option<Arc<UdpSocket>>,
    tcp_stream: Option<tokio::net::TcpStream>,
    client: Client,
    resolver_url: Arc<String>,
    data: Bytes,
    peer: SocketAddr,
    stats: Arc<Stats>,
    cache: DnsCache,
) -> Result<()> {
    let domain = extract_domain(&data);

    if data.len() > 2 {
        let cache_key = data.slice(2..);
        if let Some((cached_resp, ttl)) = cache.get(&cache_key).await {
             let mut resp = vec![0u8; cached_resp.len()];
             resp.copy_from_slice(&cached_resp);
             resp[0] = data[0];
             resp[1] = data[1];
             add_query_log(domain, format!("OK (Cache {})", ttl));
             return send_response(udp_sock, tcp_stream, Bytes::from(resp), peer).await;
        }
    }

    let config_lock = ODOH_CONFIG.read().await;
    let odoh_config = config_lock.as_ref().ok_or_else(|| anyhow::anyhow!("No ODoH Config available"))?;
    
    let mut seed_bytes = [0u8; 32];
    getrandom::getrandom(&mut seed_bytes).unwrap();
    let mut rng = StdRng::from_seed(seed_bytes);
    
    let query_plaintext = ObliviousDoHMessagePlaintext::new(&data, 0); // Convert raw DNS message to ODoH plaintext
    let config_contents: ObliviousDoHConfigContents = odoh_config.clone().into();
    let (encrypted_query_msg, client_secret) = encrypt_query(&query_plaintext, &config_contents, &mut rng)?; // Fixed: use .clone().into() for config contents
    
    let req_bytes = compose(&encrypted_query_msg)?.freeze(); // Use compose to serialize ObliviousDoHMessage

    let start = std::time::Instant::now();
    
    let resp = client.post(&*resolver_url)
        .header("content-type", "application/oblivious-dns-message")
        .header("accept", "application/oblivious-dns-message")
        .body(req_bytes)
        .send()
        .await;

    match resp {
        Ok(r) => {
            if !r.status().is_success() {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                add_query_log(domain, format!("Error {}", r.status()));
                return Err(anyhow::anyhow!("HTTP Error {}", r.status()));
            }
            let resp_bytes = r.bytes().await?;
            let mut response_cursor = Cursor::new(resp_bytes);
            let odoh_response: ObliviousDoHMessage = parse(&mut response_cursor)?; // Parse into ObliviousDoHMessage

            let dns_resp_plaintext = decrypt_response(&query_plaintext, &odoh_response, client_secret)?;
            let dns_resp = dns_resp_plaintext.into_msg().to_vec(); // Access dns_msg field via into_msg()
            
            let latency = start.elapsed().as_millis() as usize;
            LAST_LATENCY.store(latency, Ordering::Relaxed);
            add_query_log(domain, format!("OK ({}ms)", latency));

             if data.len() > 2 && dns_resp.len() > 2 {
                cache.insert(data.slice(2..), (Bytes::copy_from_slice(&dns_resp), 60)).await;
            }
            
            send_response(udp_sock, tcp_stream, Bytes::from(dns_resp), peer).await
        }
        Err(e) => {
             stats.errors.fetch_add(1, Ordering::Relaxed);
             add_query_log(domain, "Error".to_string());
             Err(e.into())
        }
    }
}

async fn send_response(
    udp_sock: Option<Arc<UdpSocket>>,
    mut tcp_stream: Option<tokio::net::TcpStream>,
    data: Bytes,
    peer: SocketAddr
) -> Result<()> {
    if let Some(s) = udp_sock {
        s.send_to(&data, peer).await?;
    } else if let Some(s) = &mut tcp_stream {
        let len = (data.len() as u16).to_be_bytes();
        s.write_all(&len).await?;
        s.write_all(&data).await?;
    }
    Ok(())
}

fn extract_domain(data: &[u8]) -> String {
    if data.len() <= 12 { return "unknown".to_string(); }
    let mut d = String::new();
    let mut i = 12;
    while i < data.len() && data[i] != 0 {
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() { break; }
        if !d.is_empty() { d.push('.'); }
        d.push_str(&String::from_utf8_lossy(&data[i..i+len]));
        i += len;
    }
    if d.is_empty() { "unknown".to_string() } else { d }
}

async fn resolve_bootstrap(domain: &str, bootstrap_dns: &str, allow_ipv6: bool) -> Result<SocketAddr> {
    use hickory_resolver::config::{ResolverConfig, NameServerConfig, ResolverOpts};
    use hickory_resolver::proto::xfer::Protocol;
    use hickory_resolver::TokioResolver;
    use hickory_resolver::name_server::TokioConnectionProvider;

    let servers: Vec<SocketAddr> = bootstrap_dns
        .split(',')
        .map(|s| {
            let s = s.trim();
            if let Ok(ip) = s.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                s.parse().expect("Invalid bootstrap address")
            }
        })
        .collect();

    let mut config = ResolverConfig::new();
    for s in servers {
        config.add_name_server(NameServerConfig::new(s, Protocol::Udp));
        config.add_name_server(NameServerConfig::new(s, Protocol::Tcp));
    }

    let mut opts = ResolverOpts::default();
    opts.ip_strategy = if allow_ipv6 {
        hickory_resolver::config::LookupIpStrategy::Ipv4thenIpv6
    } else {
        hickory_resolver::config::LookupIpStrategy::Ipv4Only
    };

    let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();
    let ips = resolver.lookup_ip(domain).await.context("Failed to resolve DoH provider")?;
    
    let ip = ips.iter().find(|ip| ip.is_ipv4()).or_else(|| ips.iter().find(|ip| ip.is_ipv6())).ok_or_else(|| anyhow::anyhow!("No IPs found"))?;
    
    Ok(SocketAddr::new(ip, 443))
}

fn create_client(config: &Config, resolver: Arc<DynamicResolver>) -> Result<Client> {
     let mut builder = Client::builder()
        .dns_resolver(resolver)
        .use_rustls_tls() 
        .pool_idle_timeout(Duration::from_secs(config.max_idle_time))
        .pool_max_idle_per_host(32) 
        .connect_timeout(Duration::from_secs(config.conn_loss_time));

    if config.http11 { builder = builder.http1_only(); }

    if let Some(source_addr) = &config.source_addr {
        if let Ok(ip) = source_addr.parse::<IpAddr>() {
            builder = builder.local_address(ip);
        }
    }
    Ok(builder.no_proxy().build()?)
}

#[cfg(feature = "jni")]
pub mod jni_api {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JClass, JObject, JString};
    use jni::sys::jint;
    use tokio::runtime::Runtime;
    use tokio_util::sync::CancellationToken;

    static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().unwrap());
    static CANCELLATION_TOKEN: LazyLock<Mutex<Option<CancellationToken>>> = LazyLock::new(|| Mutex::new(None));

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_initLogger(
        mut _env: JNIEnv,
        _class: JClass,
        _context: JObject,
    ) {
         android_logger::init_once(
            android_logger::Config::default().with_tag("OxidOH")
         );
         #[cfg(target_os = "android")]
         rustls_platform_verifier::android::init_hosted(&mut _env, _context).ok();
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_startProxy(
        mut env: JNIEnv,
        _class: JClass,
        listen_addr: JString,
        listen_port: jint,
        resolver_url: JString,
        bootstrap_dns: JString,
        allow_ipv6: jni::sys::jboolean,
        cache_ttl: jni::sys::jlong,
    ) -> jint {
        let listen_addr: String = env.get_string(&listen_addr).unwrap().into();
        let resolver_url: String = env.get_string(&resolver_url).unwrap().into();
        let bootstrap_dns: String = env.get_string(&bootstrap_dns).unwrap().into();
        
        let config = Config {
            listen_addr,
            listen_port: listen_port as u16,
            resolver_url,
            bootstrap_dns,
            allow_ipv6: allow_ipv6 != 0,
            tcp_client_limit: 20,
            polling_interval: 120,
            force_ipv4: false,
            proxy_server: None,
            source_addr: None,
            http11: false,
            http3: false,
            max_idle_time: 120,
            conn_loss_time: 10,
            ca_path: None,
            statistic_interval: 0,
            cache_ttl: cache_ttl as u64,
        };

        let token = CancellationToken::new();
        let cloned_token = token.clone();
        {
            let mut lock = CANCELLATION_TOKEN.lock().unwrap();
            *lock = Some(token);
        }
        
        let stats = Arc::new(Stats::new());

        RUNTIME.spawn(async move {
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                cloned_token.cancelled().await;
                let _ = tx.send(());
            });
            let _ = run_proxy(config, stats, rx).await;
        });

        0
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_getLatency(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        LAST_LATENCY.load(Ordering::Relaxed) as jint
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_getLogs(
        mut env: JNIEnv,
        _class: JClass,
    ) -> jni::sys::jobjectArray {
         let logs = QUERY_LOGS.lock().unwrap();
         let cls = env.find_class("java/lang/String").unwrap();
         let initial = env.new_string("").unwrap();
         let array = env.new_object_array(logs.len() as jni::sys::jsize, cls, &initial).unwrap();
         for (i, log) in logs.iter().enumerate() {
             let s = env.new_string(log).unwrap();
             env.set_object_array_element(&array, i as jni::sys::jsize, &s).unwrap();
         }
         array.into_raw()
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_stopProxy(
        _env: JNIEnv,
        _class: JClass,
    ) {
         let mut lock = CANCELLATION_TOKEN.lock().unwrap();
         if let Some(token) = lock.take() {
             token.cancel();
         }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_oxidoh_ProxyService_clearCache(
        _env: JNIEnv,
        _class: JClass,
    ) {
        RUNTIME.spawn(async {
            if let Some(cache) = &*GLOBAL_CACHE.read().await {
                cache.invalidate_all();
                debug!("DNS Cache cleared via JNI");
            }
        });
    }
}