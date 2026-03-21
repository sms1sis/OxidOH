use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use std::net::{SocketAddr, IpAddr};
use anyhow::{Result, Context};
use tokio::net::{UdpSocket, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use reqwest::{Client, Url};
use std::sync::{Arc, Mutex};
use tokio::sync::{RwLock, mpsc};

use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::collections::{VecDeque, HashMap};
use std::sync::LazyLock;
use bytes::Bytes;
use odoh_rs::{ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHMessage, ObliviousDoHMessagePlaintext, ObliviousDoHConfigContents, encrypt_query, decrypt_response, parse, compose};
use std::io::Cursor;
#[cfg(feature = "jni")]
use jni::JavaVM;
#[cfg(feature = "jni")]
use jni::objects::JClass;
use hickory_resolver::proto::op::Message;

pub struct Stats {
    pub queries_udp: AtomicUsize,
    pub queries_tcp: AtomicUsize,
    pub queries_https: AtomicUsize,
    pub cache_hits: AtomicUsize,
    pub cache_misses: AtomicUsize,
    pub malformed: AtomicUsize,
    pub errors: AtomicUsize,
    pub total_latency: AtomicUsize,
    pub latency_count: AtomicUsize,
}

struct LogMessage {
    domain: String,
    status: String,
}

static QUERY_LOGS: LazyLock<Mutex<VecDeque<String>>> = LazyLock::new(|| Mutex::new(VecDeque::with_capacity(50)));
static LOG_SENDER: LazyLock<mpsc::UnboundedSender<LogMessage>> = LazyLock::new(|| {
    let (tx, mut rx) = mpsc::unbounded_channel::<LogMessage>();
    // Use a plain OS thread (mirroring NATIVE_LOG_SENDER) so this is safe to
    // initialise before the Tokio runtime exists, e.g. during static init or
    // early in main() before #[tokio::main] sets up the executor.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("log worker runtime");
        rt.block_on(async move {
            while let Some(msg) = rx.recv().await {
                let mut logs = QUERY_LOGS.lock().unwrap();
                if logs.len() >= 50 {
                    logs.pop_front();
                }
                let timestamp = chrono::Local::now().format("%H:%M:%S").to_string();
                logs.push_back(format!("[{}] {} -> {}", timestamp, msg.domain, msg.status));
            }
        });
    });
    tx
});

enum NativeLog {
    Message { level: String, msg: String },
    Shutdown,
}

static NATIVE_LOG_SENDER: LazyLock<mpsc::UnboundedSender<NativeLog>> = LazyLock::new(|| {
    let (tx, mut rx) = mpsc::unbounded_channel::<NativeLog>();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            while let Some(entry) = rx.recv().await {
                let (level, msg) = match entry {
                    NativeLog::Shutdown => break,
                    NativeLog::Message { level, msg } => (level, msg),
                };
                // Log to Android logcat as fallback
                match level.as_str() {
                    "ERROR" => log::error!(target: "OxidOH-Native", "{}", msg),
                    "WARN"  => log::warn!(target: "OxidOH-Native", "{}", msg),
                    "INFO"  => log::info!(target: "OxidOH-Native", "{}", msg),
                    _       => log::debug!(target: "OxidOH-Native", "{}", msg),
                }
                // Forward to Kotlin via JNI — flat closure avoids nested if-let pyramid
                let _ = (|| -> Option<()> {
                    let jvm_guard   = JVM.read().ok()?;
                    let jvm   = jvm_guard.as_ref()?;
                    let class_guard = PROXY_SERVICE_CLASS.read().ok()?;
                    let class: &jni::objects::GlobalRef = class_guard.as_ref()?;
                    let mut env = jvm.attach_current_thread().ok()?;
                    let level_j = env.new_string(&level).ok()?;
                    let tag_j   = env.new_string("OxidOH-Native").ok()?;
                    let msg_j   = env.new_string(&msg).ok()?;
                    env.call_static_method(
                        class,
                        "nativeLog",
                        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
                        &[(&level_j).into(), (&tag_j).into(), (&msg_j).into()],
                    ).ok()?;
                    Some(())
                })();
            }
        });
    });
    tx
});

fn native_log(level: &str, msg: &str) {
    if !cfg!(debug_assertions) {
        match level {
            "ERROR" | "WARN" | "INFO" => {} // Always allow
            _ => return,                     // Suppress DEBUG/TRACE in release
        }
    }
    let _ = NATIVE_LOG_SENDER.send(NativeLog::Message {
        level: level.to_string(),
        msg: msg.to_string(),
    });
}

#[cfg(feature = "jni")]
static GLOBAL_STATS: LazyLock<std::sync::RwLock<Option<Arc<Stats>>>> = LazyLock::new(|| std::sync::RwLock::new(None));

#[cfg(feature = "jni")]
static GLOBAL_CACHE: LazyLock<std::sync::RwLock<Option<DnsCache>>> = LazyLock::new(|| std::sync::RwLock::new(None));

static LAST_LATENCY: AtomicUsize = AtomicUsize::new(0);

// In-flight deduplication: maps question-bytes → list of oneshot senders waiting
// for the result.  The first query for a given domain fires the ODoH fetch;
// concurrent duplicates just subscribe and share the response.
type InflightMap = Mutex<HashMap<Bytes, Vec<tokio::sync::oneshot::Sender<Result<Bytes, String>>>>>; // Bytes shared via clone (cheap arc-clone)
static INFLIGHT: LazyLock<InflightMap> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn add_query_log(domain: String, status: String) {
    if !cfg!(debug_assertions) && status.contains("DEBUG") {
        return;
    }
    let _ = LOG_SENDER.send(LogMessage { domain, status });
}

impl Stats {
    pub fn new() -> Self {
        Self {
            queries_udp: AtomicUsize::new(0),
            queries_tcp: AtomicUsize::new(0),
            queries_https: AtomicUsize::new(0),
            cache_hits: AtomicUsize::new(0),
            cache_misses: AtomicUsize::new(0),
            malformed: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            total_latency: AtomicUsize::new(0),
            latency_count: AtomicUsize::new(0),
        }
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
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
    pub odoh_target_url: String, 
    pub odoh_proxy_url: Option<String>,
    pub proxy_server: Option<String>,
    pub source_addr: Option<String>,
    pub http11: bool,
    pub http3: bool,
    pub max_idle_time: u64,
    pub conn_loss_time: u64,
    pub ca_path: Option<String>,
    pub statistic_interval: u64,
    pub cache_ttl: u64,
    pub exclude_suffixes: Option<String>, // comma-separated domain suffixes to exclude from cache
}

// ── Sharded DNS Cache ─────────────────────────────────────────────────────────
// 16-shard HashMap replaces moka to eliminate background GC threads and the
// lock contention issues they cause on Android.  Each shard holds entries as
// (response_bytes, expiry_instant) keyed by the DNS question section (ID-stripped).
const CACHE_SHARDS: usize = 16;

#[derive(Clone)]
struct DnsCache {
    shards: Arc<[Mutex<HashMap<Bytes, (Arc<Bytes>, Instant)>>; CACHE_SHARDS]>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            shards: Arc::new(std::array::from_fn(|_| Mutex::new(HashMap::new()))),
        }
    }

    fn shard_index(key: &Bytes) -> usize {
        // FNV-1a over the first 4 bytes (qtype+qname start) for fast dispatch
        let mut h: u32 = 2166136261;
        for &b in key.iter().take(8) {
            h ^= b as u32;
            h = h.wrapping_mul(16777619);
        }
        (h as usize) & (CACHE_SHARDS - 1)
    }

    fn get(&self, key: &Bytes) -> Option<(Arc<Bytes>, Instant)> {
        let idx = Self::shard_index(key);
        let shard = self.shards[idx].lock().unwrap();
        shard.get(key).map(|(b, t)| (Arc::clone(b), *t))
    }

    fn insert(&self, key: Bytes, value: (Bytes, Instant)) {
        let idx = Self::shard_index(&key);
        let mut shard = self.shards[idx].lock().unwrap();
        // Opportunistic eviction: remove expired entries in this shard
        let now = Instant::now();
        shard.retain(|_, (_, exp)| *exp > now);
        shard.insert(key, (Arc::new(value.0), value.1));
    }

    fn invalidate(&self, key: &Bytes) {
        let idx = Self::shard_index(key);
        let mut shard = self.shards[idx].lock().unwrap();
        shard.remove(key);
    }

    fn invalidate_all(&self) {
        for shard in self.shards.iter() {
            shard.lock().unwrap().clear();
        }
    }

    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }
}

#[derive(Clone)]
struct DynamicResolver {
    // Arc<Vec<>> so resolve() shares the address list without cloning it
    hosts: Arc<RwLock<HashMap<String, Arc<Vec<SocketAddr>>>>>,
}

impl DynamicResolver {
    fn new() -> Self {
        Self {
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    async fn update(&self, domain: String, addrs: Vec<SocketAddr>) {
        let mut hosts = self.hosts.write().await;
        hosts.insert(domain, Arc::new(addrs));
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
                // Collect into Vec before dropping the lock so the iterator
                // doesn't borrow from addrs which would outlive the guard.
                let addrs_vec: Vec<SocketAddr> = addrs.iter().copied().collect();
                drop(hosts);
                Ok(Box::new(addrs_vec.into_iter()) as Addrs)
            } else {
                Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound,
                    format!("Host not found: {}", name_str)))
                    as Box<dyn std::error::Error + Send + Sync>)
            }
        })
    }
}

static ODOH_CONFIG: LazyLock<std::sync::RwLock<Option<ObliviousDoHConfig>>> = LazyLock::new(|| std::sync::RwLock::new(None));
#[cfg(feature = "jni")]
static JVM: LazyLock<std::sync::RwLock<Option<JavaVM>>> = LazyLock::new(|| std::sync::RwLock::new(None));
#[cfg(feature = "jni")]
static PROXY_SERVICE_CLASS: LazyLock<std::sync::RwLock<Option<jni::objects::GlobalRef>>> = LazyLock::new(|| std::sync::RwLock::new(None));

pub async fn run_proxy(config: Config, stats: Arc<Stats>, mut shutdown_rx: tokio::sync::oneshot::Receiver<()>) -> Result<()> {
    native_log("INFO", &format!("run_proxy entered, binding {}:{}", config.listen_addr, config.listen_port));
    let addr: SocketAddr = format!("{}:{}", config.listen_addr, config.listen_port)
        .parse()
        .context("Failed to parse listen address")?;

    let target_url_parsed = Url::parse(&config.odoh_target_url)
        .context("Failed to parse target URL")?;
    let target_domain = target_url_parsed.domain().context("Target URL must have a domain")?.to_string();

    // Bind using std::net directly — socket2's SO_REUSEPORT setsockopt call
    // hangs indefinitely on Android under certain SELinux policies (untrusted_app
    // is denied cgroup access and the kernel blocks in the syscall path).
    // std::net bind uses only the minimum required socket options and is always
    // permitted for untrusted_app.
    let mut udp_socket = None;
    let mut tcp_listener = None;
    for i in 0..5 {
        let bind_res = tokio::task::spawn_blocking({
            let addr = addr;
            move || -> Result<(std::net::UdpSocket, std::net::TcpListener)> {
                let udp = std::net::UdpSocket::bind(addr)?;
                udp.set_nonblocking(true)?;
                let tcp = std::net::TcpListener::bind(addr)?;
                tcp.set_nonblocking(true)?;
                Ok((udp, tcp))
            }
        }).await.context("spawn_blocking panicked")??;

        match (UdpSocket::from_std(bind_res.0), TcpListener::from_std(bind_res.1)) {
            (Ok(u), Ok(t)) => {
                udp_socket = Some(Arc::new(u));
                tcp_listener = Some(t);
                break;
            }
            (Err(e), _) | (_, Err(e)) => {
                native_log("WARN", &format!("Failed to convert socket (attempt {}): {}", i, e));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let udp_socket = udp_socket.context("Failed to bind UDP")?;
    let tcp_listener = tcp_listener.context("Failed to bind TCP")?;

    native_log("INFO", &format!("Listening on {} -> ODoH Target {}", addr, config.odoh_target_url));

    let dynamic_resolver = DynamicResolver::new();
    // Also bootstrap one.one.one.one just in case Cloudflare Target uses it internally
    if let Ok(ip) = "1.1.1.1".parse::<IpAddr>() {
        dynamic_resolver.update("one.one.one.one".to_string(), vec![SocketAddr::new(ip, 443)]).await;
    }

    // Hardcoded fallbacks for common relays and targets
    if let Ok(ip) = "172.67.140.94".parse::<IpAddr>() {
        dynamic_resolver.update("odoh-jp.tiarap.org".to_string(), vec![SocketAddr::new(ip, 443)]).await;
        dynamic_resolver.update("odoh.crypto.sx".to_string(), vec![SocketAddr::new(ip, 443)]).await;
    }
    if let Ok(ip) = "151.101.1.51".parse::<IpAddr>() {
        dynamic_resolver.update("odoh-relay.edgecompute.app".to_string(), vec![SocketAddr::new(ip, 443)]).await;
    }
    if let Ok(ip) = "174.138.29.175".parse::<IpAddr>() {
        dynamic_resolver.update("doh.tiarap.org".to_string(), vec![SocketAddr::new(ip, 443)]).await;
        dynamic_resolver.update("jp.tiar.app".to_string(), vec![SocketAddr::new(ip, 443)]).await;
    }

    let ips = resolve_bootstrap(&target_domain, &config.bootstrap_dns, config.allow_ipv6, Some(&dynamic_resolver)).await?;
    native_log("INFO", &format!("Bootstrapped Target {} to {:?}", target_domain, ips));
    
    dynamic_resolver.update(target_domain.clone(), ips).await;

    if let Some(proxy_url) = &config.odoh_proxy_url {
        let proxy_url_parsed = Url::parse(proxy_url).context("Failed to parse ODoH Proxy URL")?;
        let proxy_domain = proxy_url_parsed.domain().context("Proxy URL must have a domain")?.to_string();
        let proxy_ips = resolve_bootstrap(&proxy_domain, &config.bootstrap_dns, config.allow_ipv6, Some(&dynamic_resolver)).await?;
        native_log("INFO", &format!("Bootstrapped Proxy {} to {:?}", proxy_domain, proxy_ips));
        dynamic_resolver.update(proxy_domain, proxy_ips).await;
    }

    let client = create_client(&config, Arc::new(dynamic_resolver))?;
    
    let mut fetched_config = None;
    for attempt in 1..=5 {
        native_log("INFO", &format!("Fetching ODoH config from {} (Attempt {}/5)", config.odoh_target_url, attempt));
        match fetch_odoh_config(&client, &config.odoh_target_url).await {
            Ok(c) => {
                fetched_config = Some(c);
                native_log("INFO", "Fetched ODoH Config successfully");
                break;
            }
            Err(e) => {
                if attempt < 5 {
                    native_log("WARN", &format!("Failed to fetch ODoH Config (Attempt {}): {:?}. Retrying in 2s...", attempt, e));
                    tokio::time::sleep(Duration::from_secs(2)).await;
                } else {
                    native_log("ERROR", &format!("Failed to fetch ODoH Config after 5 attempts: {:?}. Proxy will likely fail.", e));
                }
            }
        }
    }

    if let Some(c) = fetched_config {
        if let Ok(mut w) = ODOH_CONFIG.write() {
            *w = Some(c);
        }
    }

    // Background task to refresh ODoH config periodically (every 1 hour).
    // Use interval_at so the first tick fires after 1 hour, not immediately.
    let config_refresh_handle = {
        let client = client.clone();
        let target_url = config.odoh_target_url.clone();
        tokio::spawn(async move {
            let start = tokio::time::Instant::now() + Duration::from_secs(3600);
            let mut interval = tokio::time::interval_at(start, Duration::from_secs(3600));
            loop {
                interval.tick().await;
                native_log("INFO", "Periodically refreshing ODoH config...");
                match fetch_odoh_config(&client, &target_url).await {
                    Ok(c) => {
                        if let Ok(mut w) = ODOH_CONFIG.write() {
                            *w = Some(c);
                            native_log("INFO", "ODoH config refreshed successfully");
                        }
                    }
                    Err(e) => native_log("WARN", &format!("Failed to refresh ODoH config: {:?}", e)),
                }
            }
        })
    };

    let send_url = if let Some(proxy_url) = &config.odoh_proxy_url {
        let target_url = Url::parse(&config.odoh_target_url).context("Failed to parse target URL")?;
        let connector = if proxy_url.contains('?') { "&" } else { "?" };
        
        let url = format!("{}{}targethost={}&targetpath={}", 
            proxy_url, 
            connector,
            target_url.host_str().unwrap_or(""),
            target_url.path() // This keeps /dns-query as raw string
        );
        
        native_log("INFO", &format!("Using Relay URL: {}", url));
        url
    } else {
        config.odoh_target_url.clone()
    };
    
    let send_url_str = Arc::new(send_url);
    
    let cache: DnsCache = DnsCache::new();

    #[cfg(feature = "jni")]
    {
        if let Ok(mut w) = GLOBAL_CACHE.write() {
            *w = Some(cache.clone());
        }
    }

    native_log("INFO", "Starting proxy loops");

    let target_url_str = Arc::new(config.odoh_target_url.clone());
    let proxy_url_str = config.odoh_proxy_url.as_ref().map(|s| Arc::new(s.clone()));
    let cache_ttl = config.cache_ttl;
    let exclude_suffixes = config.exclude_suffixes.clone();

    let mut udp_loop = {
        let socket = udp_socket.clone();
        let client = client.clone();
        let resolver_url = send_url_str.clone();
        let target_url = target_url_str.clone();
        let proxy_url = proxy_url_str.clone();
        let stats = stats.clone();
        let cache = cache.clone();
        let exclude_suffixes = exclude_suffixes.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let data = Bytes::copy_from_slice(&buf[..len]);
                        let socket = socket.clone();
                        let client = client.clone();
                        let resolver_url = resolver_url.clone();
                        let target_url = target_url.clone();
                        let proxy_url = proxy_url.clone();
                        let stats = stats.clone();
                        let cache = cache.clone();
                        let exclude_suffixes = exclude_suffixes.clone();
                        tokio::spawn(async move {
                            stats.queries_udp.fetch_add(1, Ordering::Relaxed);
                            #[cfg(debug_assertions)] native_log("DEBUG", &format!("Handling UDP query from {}", peer));
                            if let Err(e) = handle_query(Some(socket), None, client, resolver_url, target_url, proxy_url, data, peer, stats, cache, cache_ttl, exclude_suffixes).await {
                                native_log("ERROR", &format!("UDP error: {}", e));
                            }
                        });
                    }
                    Err(e) => {
                        native_log("ERROR", &format!("UDP recv_from error: {}", e));
                        // Only break on unrecoverable errors; transient errors (EAGAIN) are retried.
                        if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::Interrupted {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                        break;
                    }
                }
            }
        })
    };

    let mut tcp_loop = {
         let listener = tcp_listener;
         let client = client.clone();
         let resolver_url = send_url_str.clone();
         let target_url = target_url_str.clone();
         let proxy_url = proxy_url_str.clone();
         let stats = stats.clone();
         let cache = cache.clone();
         let exclude_suffixes = exclude_suffixes.clone();
         tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, peer)) => {
                        let client = client.clone();
                        let resolver_url = resolver_url.clone();
                        let target_url = target_url.clone();
                        let proxy_url = proxy_url.clone();
                        let stats = stats.clone();
                        let cache = cache.clone();
                        let exclude_suffixes = exclude_suffixes.clone();
                        tokio::spawn(async move {
                            stats.queries_tcp.fetch_add(1, Ordering::Relaxed);
                            let mut len_buf = [0u8; 2];
                            if stream.read_exact(&mut len_buf).await.is_ok() {
                                let len = u16::from_be_bytes(len_buf) as usize;
                                // Guard against zero-length or oversized messages
                                if len == 0 || len > 65535 {
                                    stats.malformed.fetch_add(1, Ordering::Relaxed);
                                    return;
                                }
                                let mut data = vec![0u8; len];
                                if stream.read_exact(&mut data).await.is_ok() {
                                    if extract_domain(&data) == "unknown" {
                                        stats.malformed.fetch_add(1, Ordering::Relaxed);
                                    }
                                    let _ = handle_query(None, Some(stream), client, resolver_url, target_url, proxy_url, Bytes::from(data), peer, stats, cache, cache_ttl, exclude_suffixes).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        native_log("WARN", &format!("TCP accept error: {}", e));
                        // Brief back-off to avoid spinning on repeated accept failures
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
         })
    };

    tokio::select! {
        _ = &mut shutdown_rx => {
            native_log("INFO", "Shutting down: Aborting loops");
            udp_loop.abort();
            tcp_loop.abort();
            config_refresh_handle.abort();
        },
        _ = &mut udp_loop => {
            native_log("WARN", "UDP loop exited unexpectedly");
            tcp_loop.abort();
            config_refresh_handle.abort();
        },
        _ = &mut tcp_loop => {
            native_log("WARN", "TCP loop exited unexpectedly");
            udp_loop.abort();
            config_refresh_handle.abort();
        },
    }
    Ok(())
}

async fn fetch_odoh_config(client: &Client, target_url: &str) -> Result<ObliviousDoHConfig> {
    let parsed = Url::parse(target_url).context("Invalid target URL")?;
    let host = parsed.host_str().context("Target URL must have a host")?;
    let scheme = parsed.scheme();
    
    // Multiple standard and fallback paths
    let mut urls = vec![
        format!("{}://{}/.well-known/odohconfigs", scheme, host),
        format!("{}://{}/odohconfigs", scheme, host),
    ];
    
    if target_url.ends_with('/') {
        urls.push(format!("{}.well-known/odohconfigs", target_url));
        urls.push(format!("{}odohconfigs", target_url));
    } else {
        urls.push(format!("{}/.well-known/odohconfigs", target_url));
        urls.push(format!("{}/odohconfigs", target_url));
    }
    urls.push(target_url.to_string());

    let mut last_err = anyhow::anyhow!("No config paths tried");

    for url in urls {
        for attempt in 0..2 {
            let ua = if attempt == 0 { "dnscrypt-proxy" } else { "oxidoh/0.3.0" };
            native_log("DEBUG", &format!("Trying odohconfigs from {} (UA: {})", url, ua));
            
            let resp = client.get(&url)
                .header("User-Agent", ua)
                .header("Accept", "application/oblivious-dns-message-config, application/octet-stream")
                .header("Cache-Control", "no-cache, max-age=0")
                .timeout(Duration::from_secs(5))
                .send()
                .await;

            match resp {
                Ok(r) => {
                    let status = r.status();
                    if status.is_success() {
                        let bytes = r.bytes().await?;
                        if bytes.is_empty() {
                            native_log("WARN", &format!("Empty config from {}", url));
                            continue;
                        }
                        native_log("DEBUG", &format!("Fetched {} bytes from {}", bytes.len(), url));
                        let mut cursor = Cursor::new(bytes.clone()); 
                        match parse::<ObliviousDoHConfigs, _>(&mut cursor) {
                            Ok(configs) => {
                                if let Some(config) = configs.supported().into_iter().next() {
                                    native_log("INFO", &format!("Successfully fetched ODoH config from {}", url));
                                    return Ok(config);
                                }
                            }
                            Err(e) => {
                                native_log("DEBUG", &format!("Failed to parse as ObliviousDoHConfigs: {:?}. Content (hex): {:02x?}", e, &bytes[..std::cmp::min(bytes.len(), 16)]));
                                // Try parsing as single config if multiple failed
                                let mut cursor2 = Cursor::new(bytes);
                                if let Ok(config) = parse::<ObliviousDoHConfig, _>(&mut cursor2) {
                                    native_log("INFO", &format!("Successfully fetched single ODoH config from {}", url));
                                    return Ok(config);
                                }
                            }
                        }
                    } else {
                        native_log("DEBUG", &format!("Path {} returned status {}", url, status));
                        last_err = anyhow::anyhow!("Path {} returned status {}", url, status);
                    }
                }
                Err(e) => {
                    native_log("DEBUG", &format!("Error reaching {}: {:?}", url, e));
                    last_err = e.into();
                }
            }
        }
    }
    Err(last_err)
}

async fn handle_query(
    udp_sock: Option<Arc<UdpSocket>>,
    tcp_stream: Option<tokio::net::TcpStream>,
    client: Client,
    resolver_url: Arc<String>,
    target_url_str: Arc<String>,
    proxy_url_str: Option<Arc<String>>,
    data: Bytes,
    peer: SocketAddr,
    stats: Arc<Stats>,
    cache: DnsCache,
    cache_ttl_default: u64,
    exclude_suffixes: Option<String>,
) -> Result<()> {
    if data.len() < 12 {
        return Err(anyhow::anyhow!("DNS message too short"));
    }

    let original_id = [data[0], data[1]];
    let domain = extract_domain(&data);
    let should_cache = if let Some(ref suffixes) = exclude_suffixes {
        !suffixes.split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .any(|suffix| domain.eq_ignore_ascii_case(suffix) || domain.ends_with(&format!(".{}", suffix)))
    } else {
        true
    };

    let cache_key = data.slice(2..);

    if should_cache {
        if let Some((cached_resp, expiry)) = cache.get(&cache_key) {
            if Instant::now() < expiry {
                // Arc<Bytes> — clone is O(1), no heap allocation for cache hits
                let mut resp = cached_resp.to_vec();
                resp[0] = original_id[0];
                resp[1] = original_id[1];
                zero_ttls_in_response(&mut resp);
                stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                add_query_log(domain, "OK (Cache)".to_string());
                return send_response(udp_sock, tcp_stream, Bytes::from(resp), peer).await;
            } else {
                cache.invalidate(&cache_key);
            }
        }
    }

    stats.cache_misses.fetch_add(1, Ordering::Relaxed);

    // ── In-flight deduplication ───────────────────────────────────────────────
    // If another task is already fetching this exact question, subscribe and
    // wait for its result instead of firing a duplicate ODoH request.
    let (is_leader, rx) = {
        let mut inflight = INFLIGHT.lock().unwrap();
        if let Some(waiters) = inflight.get_mut(&cache_key) {
            let (tx, rx) = tokio::sync::oneshot::channel();
            waiters.push(tx);
            (false, Some(rx))
        } else {
            inflight.insert(cache_key.clone(), Vec::new());
            (true, None)
        }
    };

    if !is_leader {
        // Follower: wait for the leader's result
        match rx.unwrap().await {
            Ok(Ok(dns_resp)) => {
                let mut resp = dns_resp.to_vec();
                resp[0] = original_id[0];
                resp[1] = original_id[1];
                zero_ttls_in_response(&mut resp);
                stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                stats.cache_misses.fetch_sub(1, Ordering::Relaxed); // was not a true miss
                add_query_log(domain, "OK (Dedup)".to_string());
                return send_response(udp_sock, tcp_stream, Bytes::from(resp), peer).await;
            }
            Ok(Err(e)) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                return Err(anyhow::anyhow!("Dedup leader failed: {}", e));
            }
            Err(_) => {
                // Leader dropped without sending — fall through to our own fetch
            }
        }
    }

    stats.queries_https.fetch_add(1, Ordering::Relaxed);

    let start = std::time::Instant::now();
    let mut last_err = None;
    let mut final_resp = None;

    for attempt in 1..=3 {
        if attempt > 1 {
            tokio::time::sleep(Duration::from_millis(100 * (attempt - 1))).await;
        }

        let mut odoh_config_opt = {
            let lock = ODOH_CONFIG.read().map_err(|_| anyhow::anyhow!("Lock error"))?;
            lock.as_ref().cloned()
        };

        if odoh_config_opt.is_none() {
            native_log("WARN", "ODoH Config missing in handle_query, attempting on-demand fetch...");
            match fetch_odoh_config(&client, &*target_url_str).await {
                Ok(c) => {
                    if let Ok(mut w) = ODOH_CONFIG.write() {
                        *w = Some(c.clone());
                    }
                    odoh_config_opt = Some(c);
                }
                Err(e) => {
                    add_query_log(domain.clone(), "Error (Config Fetch Failed)".to_string());
                    last_err = Some(e);
                    continue;
                }
            }
        }

        let odoh_config = odoh_config_opt.expect("odoh_config_opt is Some after fetch/check");
        let padded_len = if data.len() <= 128 { 128 } else { data.len().next_power_of_two() };
        let padding = padded_len.saturating_sub(data.len());
        let query_plaintext = ObliviousDoHMessagePlaintext::new(&data, padding);
        let config_contents: ObliviousDoHConfigContents = odoh_config.into();

        // Scope the rng tightly so it is dropped before the first .await.
        // ThreadRng contains Rc<> and is !Send — it cannot live across an await
        // point inside tokio::spawn. rand::rng() is the rand 0.9 name for thread_rng().
        let (req_bytes, client_secret) = {
            let mut rng = rand::rng();
            let (encrypted_query_msg, client_secret) = encrypt_query(&query_plaintext, &config_contents, &mut rng)?;
            (compose(&encrypted_query_msg)?.freeze(), client_secret)
        }; // rng dropped here, before any .await 

        #[cfg(debug_assertions)] native_log("DEBUG", &format!("Sending ODoH query for {} to {} (padded to {} bytes, attempt {})", domain, resolver_url, padded_len, attempt));

        let resp = client.post(&*resolver_url)
            .header("content-type", "application/oblivious-dns-message")
            .header("accept", "application/oblivious-dns-message")
            .header("user-agent", "oxidoh/0.3.0")
            .header("proxy-connection", "keep-alive")
            .header("cache-control", "no-cache")
            .body(req_bytes.clone())
            .send()
            .await;

        // Fallback logic for different relay styles.
        // We capture the status *before* dropping the borrow so we can
        // reassign retry_resp inside the same block without fighting the borrow checker.
        let initial_status = resp.as_ref().ok().map(|r| r.status());
        let mut retry_resp = resp;

        if let Some(status) = initial_status {
            let needs_fallback = status == reqwest::StatusCode::METHOD_NOT_ALLOWED
                || status.as_u16() == 530
                || status == reqwest::StatusCode::NOT_FOUND;

            if needs_fallback {
                native_log("WARN", &format!("Relay returned {}, trying fallback...", status));

                if status == reqwest::StatusCode::METHOD_NOT_ALLOWED {
                    // GET fallback: encode the encrypted query as a base64url query param
                    let b64_query = URL_SAFE_NO_PAD.encode(&req_bytes);
                    let mut get_url = Url::parse(&*resolver_url)?;
                    get_url.query_pairs_mut().append_pair("dns", &b64_query);
                    native_log("INFO", &format!("Trying GET fallback: {}", get_url));
                    retry_resp = client
                        .get(get_url)
                        .header("accept", "application/oblivious-dns-message")
                        .header("user-agent", "oxidoh/0.3.0")
                        .send()
                        .await;
                } else if let Some(ref base_proxy) = proxy_url_str {
                    // Path-based fallback: embed target host+path in the relay URL
                    let target_url = Url::parse(&*target_url_str)
                        .context("Failed to parse target URL for fallback")?;
                    let fallback_url = format!(
                        "{}/{}{}", 
                        base_proxy.trim_end_matches('/'),
                        target_url.host_str().unwrap_or(""),
                        target_url.path()
                    );
                    native_log("INFO", &format!("Path-based fallback URL: {}", fallback_url));
                    retry_resp = client
                        .post(&fallback_url)
                        .header("content-type", "application/oblivious-dns-message")
                        .header("accept", "application/oblivious-dns-message")
                        .header("user-agent", "oxidoh/0.3.0")
                        .body(req_bytes.clone())
                        .send()
                        .await;
                }
            }
        }

        match retry_resp {
            Ok(r) => {
                if r.status() == reqwest::StatusCode::UNAUTHORIZED {
                    native_log("WARN", "ODoH Target returned 401: Invalidating config and retrying...");
                    if let Ok(mut w) = ODOH_CONFIG.write() {
                        *w = None;
                    }
                    last_err = Some(anyhow::anyhow!("HTTP 401 (Unauthorized/Expired Config)"));
                    continue;
                }
                if !r.status().is_success() {
                    let status_code = r.status().as_u16();
                    last_err = Some(anyhow::anyhow!("HTTP {}", status_code));
                    continue;
                }
                let resp_bytes = r.bytes().await?;
                
                let mut response_cursor = Cursor::new(resp_bytes.clone());
                let odoh_response: ObliviousDoHMessage = match parse(&mut response_cursor) {
                    Ok(m) => m,
                    Err(e) => {
                        native_log("ERROR", &format!("Failed to parse ODoH message: {:?}", e));
                        last_err = Some(e.into());
                        continue;
                    }
                };

                let dns_resp_plaintext = decrypt_response(&query_plaintext, &odoh_response, client_secret)?;
                let dns_resp = dns_resp_plaintext.into_msg().to_vec(); 
                
                let latency = start.elapsed().as_millis() as usize;
                LAST_LATENCY.store(latency, Ordering::Relaxed);
                stats.total_latency.fetch_add(latency, Ordering::Relaxed);
                stats.latency_count.fetch_add(1, Ordering::Relaxed);
                add_query_log(domain.clone(), format!("OK ({}ms, att {})", latency, attempt));

                // Cache the raw response (with real TTLs) for reuse.
                // Negative responses (NXDOMAIN / NODATA) are also cached using
                // the SOA minimum TTL from the authority section, preventing
                // repeated upstream lookups for non-existent domains.
                if should_cache && dns_resp.len() > 2 {
                    let mut ttl = cache_ttl_default;
                    if let Ok(msg) = Message::from_vec(&dns_resp) {
                        let rcode = msg.response_code();
                        let is_negative = rcode == hickory_resolver::proto::op::ResponseCode::NXDomain
                            || (rcode == hickory_resolver::proto::op::ResponseCode::NoError
                                && msg.answers().is_empty());
                        if is_negative {
                            // Use SOA minimum TTL for negative caching (RFC 2308)
                            ttl = msg.name_servers().iter()
                                .filter_map(|rr| {
                                    if let hickory_resolver::proto::rr::RData::SOA(soa) = rr.data() {
                                        Some(soa.minimum() as u64)
                                    } else { None }
                                })
                                .next()
                                .unwrap_or(60)
                                .clamp(30, 300);
                        } else {
                            ttl = msg.answers().iter().map(|a| a.ttl()).min()
                                .unwrap_or(cache_ttl_default as u32) as u64;
                            ttl = ttl.clamp(10, 3600);
                        }
                    }
                    let expiry = Instant::now() + Duration::from_secs(ttl);
                    cache.insert(cache_key.clone(), (Bytes::copy_from_slice(&dns_resp), expiry));
                }

                // Notify in-flight waiters — Arc so all waiters share one allocation
                {
                    let shared = Arc::new(Bytes::copy_from_slice(&dns_resp));
                    let mut inflight = INFLIGHT.lock().unwrap();
                    if let Some(waiters) = inflight.remove(&cache_key) {
                        for tx in waiters {
                            let _ = tx.send(Ok(Bytes::clone(&shared)));
                        }
                    }
                }

                final_resp = Some(dns_resp);
                break;
            }
            Err(e) => {
                last_err = Some(e.into());
            }
        }
    }

    if let Some(dns_resp) = final_resp {
        let mut resp = dns_resp.to_vec();
        resp[0] = original_id[0];
        resp[1] = original_id[1];
        zero_ttls_in_response(&mut resp);
        send_response(udp_sock, tcp_stream, Bytes::from(resp), peer).await
    } else {
        // Notify waiters of failure before returning error
        {
            let mut inflight = INFLIGHT.lock().unwrap();
            if let Some(waiters) = inflight.remove(&cache_key) {
                let err_str = last_err.as_ref().map(|e| e.to_string())
                    .unwrap_or_else(|| "Unknown error".to_string());
                for tx in waiters {
                    let _ = tx.send(Err(err_str.clone()));
                }
            }
        }
        stats.errors.fetch_add(1, Ordering::Relaxed);
        let err_msg = if let Some(ref e) = last_err { e.to_string() } else { "Unknown error".to_string() };
        native_log("ERROR", &format!("Request for {} failed after 3 attempts: {}", domain, err_msg));
        
        let err_str = if let Some(e) = last_err {
            let msg = e.to_string();
            if msg.contains("connection closed") { "Error (Conn Closed)".to_string() }
            else if msg.contains("timed out") { "Error (Timeout)".to_string() }
            else { format!("Error ({})", msg) }
        } else {
            "Error (Unknown)".to_string()
        };
        add_query_log(domain, err_str);
        Err(anyhow::anyhow!("Request failed: {}", err_msg))
    }
}

/// Zero out all TTL fields in a DNS response so the Android resolver always
/// re-queries us.  Our cache manages real freshness; this keeps latency low by
/// preventing the OS from caching stale entries between restarts.
fn zero_ttls_in_response(resp: &mut Vec<u8>) {
    // DNS wire format: 12-byte header, then question section, then RR sections.
    // Each resource record has: name (variable), type(2), class(2), TTL(4), rdlength(2), rdata.
    // We skip the question section and zero TTL bytes in answer/authority/additional.
    if resp.len() < 12 { return; }
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    let nscount = u16::from_be_bytes([resp[8], resp[9]]) as usize;
    let arcount = u16::from_be_bytes([resp[10], resp[11]]) as usize;
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let total_rrs = ancount + nscount + arcount;
    if total_rrs == 0 { return; }

    let mut pos = 12usize;
    // Skip question section
    for _ in 0..qdcount {
        // Skip name
        while pos < resp.len() {
            let len = resp[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xC0) == 0xC0 { pos += 2; break; } // pointer
            pos += len + 1;
        }
        pos += 4; // qtype + qclass
    }
    // Zero TTL in each RR
    for _ in 0..total_rrs {
        if pos >= resp.len() { break; }
        // Skip name
        while pos < resp.len() {
            let len = resp[pos] as usize;
            if len == 0 { pos += 1; break; }
            if (len & 0xC0) == 0xC0 { pos += 2; break; }
            pos += len + 1;
        }
        if pos + 10 > resp.len() { break; }
        pos += 4; // type + class
        // Zero TTL (4 bytes)
        resp[pos] = 0; resp[pos+1] = 0; resp[pos+2] = 0; resp[pos+3] = 0;
        pos += 4;
        let rdlen = u16::from_be_bytes([resp[pos], resp[pos+1]]) as usize;
        pos += 2 + rdlen;
    }
}

async fn send_response(
    udp_sock: Option<Arc<UdpSocket>>,
    mut tcp_stream: Option<tokio::net::TcpStream>,
    data: Bytes,
    peer: SocketAddr
) -> Result<()> {
    #[cfg(debug_assertions)] native_log("DEBUG", &format!("Sending response of {} bytes back to {}", data.len(), peer));
    if let Some(s) = udp_sock {
        s.send_to(&data, peer).await?;
    } else if let Some(s) = &mut tcp_stream {
        // RFC 1035 §4.2.2: DNS/TCP messages are prefixed with a 2-byte length.
        // A response larger than 65535 bytes is malformed; return an error rather
        // than silently truncating the length field.
        let len = u16::try_from(data.len())
            .map_err(|_| anyhow::anyhow!("DNS response too large for TCP framing ({} bytes)", data.len()))?;
        // Single vectored write: length prefix + data in one syscall
        let len_bytes = len.to_be_bytes();
        let mut framed = Vec::with_capacity(2 + data.len());
        framed.extend_from_slice(&len_bytes);
        framed.extend_from_slice(&data);
        s.write_all(&framed).await?;
    }
    Ok(())
}

fn extract_domain(data: &[u8]) -> String {
    if let Ok(msg) = Message::from_vec(data) {
        if let Some(query) = msg.queries().first() {
            let name = query.name().to_string();
            return if name.ends_with('.') && name.len() > 1 {
                name[..name.len() - 1].to_string()
            } else {
                name
            };
        }
    }

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

async fn resolve_bootstrap(domain: &str, bootstrap_dns: &str, allow_ipv6: bool, dynamic_resolver: Option<&DynamicResolver>) -> Result<Vec<SocketAddr>> {
    if let Some(resolver) = dynamic_resolver {
        let hosts = resolver.hosts.read().await;
        if let Some(addrs) = hosts.get(domain) {
            if !addrs.is_empty() {
                native_log("INFO", &format!("Using cached/hardcoded bootstrap for {}: {:?}", domain, addrs));
                return Ok(addrs.to_vec());
            }
        }
    }

    use hickory_resolver::config::{ResolverConfig, NameServerConfig, ResolverOpts, LookupIpStrategy};
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
        LookupIpStrategy::Ipv4AndIpv6
    } else {
        LookupIpStrategy::Ipv4Only
    };

    let resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default())
        .with_options(opts)
        .build();
    
    native_log("DEBUG", &format!("Resolving {} using bootstrap...", domain));
    let ips = match resolver.lookup_ip(domain).await {
        Ok(ips) => ips,
        Err(e) => {
            native_log("WARN", &format!("Full dual-stack lookup failed for {}, retrying with fallback nameservers: {:?}", domain, e));
            let mut opts4 = ResolverOpts::default();
            opts4.ip_strategy = LookupIpStrategy::Ipv4Only;
            
            // Try Cloudflare AND Google as fallbacks
            let mut fallback_config = ResolverConfig::cloudflare();
            fallback_config.add_name_server(NameServerConfig::new("8.8.8.8:53".parse()?, Protocol::Udp));
            fallback_config.add_name_server(NameServerConfig::new("8.8.4.4:53".parse()?, Protocol::Udp));

            let resolver4 = TokioResolver::builder_with_config(fallback_config, TokioConnectionProvider::default())
                .with_options(opts4)
                .build();
            resolver4.lookup_ip(domain).await.context("Failed to resolve DoH provider (IPv4 retry)")?
        }
    };
    
    let addrs: Vec<SocketAddr> = ips.iter().map(|ip| SocketAddr::new(ip, 443)).collect();
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("No IPs found for {}", domain));
    }
    
    Ok(addrs)
}

fn create_client(config: &Config, resolver: Arc<DynamicResolver>) -> Result<Client> {
    let mut builder = Client::builder()
        .user_agent("OxidOH/0.3.0")
        .dns_resolver(resolver)
        .use_rustls_tls()
        .http2_adaptive_window(true)
        .tcp_keepalive(Some(Duration::from_secs(60)))
        .pool_idle_timeout(Duration::from_secs(60))
        .pool_max_idle_per_host(16)
        .connect_timeout(Duration::from_secs(15));

    // Some ODoH proxies/relays (e.g. Hiddify) present CA certs as end-entity certs.
    // Only bypass TLS verification when a proxy is configured; direct target connections
    // should always be fully verified.
    if config.odoh_proxy_url.is_some() {
        native_log("WARN", "ODoH Proxy configured: allowing invalid certificates for proxy compatibility");
        builder = builder.danger_accept_invalid_certs(true);
    }

    if config.http11 { builder = builder.http1_only(); }

    if let Some(source_addr) = &config.source_addr {
        if let Ok(ip) = source_addr.parse::<IpAddr>() {
            builder = builder.local_address(ip);
        }
    }
    let client = builder.no_proxy().build()?;
    native_log("INFO", "HTTP Client created successfully");
    Ok(client)
}

fn extract_urls(input: &str) -> Vec<String> {
    // Compile the regex only once for the lifetime of the process.
    static URL_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
        regex::Regex::new(r"(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]")
            .expect("URL regex is valid")
    });
    URL_RE.find_iter(input)
        .map(|m| m.as_str().to_string())
        .collect()
}

#[cfg(feature = "jni")]
pub mod jni_api {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JObject, JString};
    use jni::sys::jint;
    use tokio::runtime::Runtime;
    use tokio_util::sync::CancellationToken;

    static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| Runtime::new().unwrap());
    static CANCELLATION_TOKEN: LazyLock<Mutex<Option<CancellationToken>>> = LazyLock::new(|| Mutex::new(None));

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_initLogger(
        mut env: JNIEnv,
        _class: JClass,
        _context: JObject,
    ) {
         let filter = if cfg!(debug_assertions) {
             log::LevelFilter::Debug
         } else {
             log::LevelFilter::Info
         };

         android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(filter)
                .with_tag("OxidOH")
         );
         
         if let Ok(jvm) = env.get_java_vm() {
             if let Ok(mut w) = JVM.write() {
                 *w = Some(jvm);
             }
         }

         if let Ok(class) = env.find_class("io/github/sms1sis/oxidoh/ProxyService") {
             if let Ok(global_ref) = env.new_global_ref(class) {
                 if let Ok(mut w) = PROXY_SERVICE_CLASS.write() {
                     *w = Some(global_ref);
                 }
             }
         }

         #[cfg(target_os = "android")]
         rustls_platform_verifier::android::init_hosted(&mut env, _context).ok();
         native_log("INFO", "Logger, JVM and Global Class Ref initialized");
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_startProxy(
        mut env: JNIEnv,
        _class: JClass,
        listen_addr: JString,
        listen_port: jint,
        resolver_url: JString,
        bootstrap_dns: JString,
        allow_ipv6: jni::sys::jboolean,
        cache_ttl: jni::sys::jlong,
        tcp_limit: jint,
        poll_interval: jni::sys::jlong,
        use_http3: jni::sys::jboolean,
        exclude_domain: JString,
    ) -> jint {
        let listen_addr: String = env.get_string(&listen_addr).unwrap().into();
        let resolver_url_input: String = env.get_string(&resolver_url).unwrap().into();
        let bootstrap_dns: String = env.get_string(&bootstrap_dns).unwrap().into();
        let exclude_domain: String = env.get_string(&exclude_domain).unwrap().into();
        
        let urls = extract_urls(&resolver_url_input);
        if urls.is_empty() {
            native_log("ERROR", "No valid URLs found in resolver input");
            return -1;
        }

        let odoh_target_url = urls[0].clone();
        let odoh_proxy_url = if urls.len() > 1 { Some(urls[1].clone()) } else { None };

        // Clear existing ODoH config to ensure a fresh fetch for the new provider
        if let Ok(mut w) = ODOH_CONFIG.write() {
            *w = None;
        }

        native_log("INFO", &format!("startProxy: addr={}, port={}, target={}, proxy={:?}", listen_addr, listen_port, odoh_target_url, odoh_proxy_url));

        let config = Config {
            listen_addr,
            listen_port: listen_port as u16,
            odoh_target_url,
            odoh_proxy_url,
            bootstrap_dns,
            allow_ipv6: allow_ipv6 != 0,
            tcp_client_limit: tcp_limit as usize,
            polling_interval: poll_interval as u64,
            force_ipv4: false,
            proxy_server: None,
            source_addr: None,
            http11: false,
            http3: use_http3 != 0,
            max_idle_time: 120,
            conn_loss_time: 10,
            ca_path: None,
            statistic_interval: 0,
            cache_ttl: cache_ttl as u64,
            exclude_suffixes: if exclude_domain.is_empty() { None } else { Some(exclude_domain) },
        };

        let token = CancellationToken::new();
        let cloned_token = token.clone();
        {
            let mut lock = CANCELLATION_TOKEN.lock().unwrap();
            *lock = Some(token);
        }
        
        let stats = Arc::new(Stats::new());
        if let Ok(mut w) = GLOBAL_STATS.write() {
            *w = Some(stats.clone());
        }

        let _handle = RUNTIME.spawn(async move {
            native_log("INFO", "Proxy task started inside runtime");
            let (tx, rx) = tokio::sync::oneshot::channel();
            tokio::spawn(async move {
                cloned_token.cancelled().await;
                native_log("INFO", "Cancellation token triggered, sending shutdown signal");
                let _ = tx.send(());
            });
            native_log("INFO", "Calling run_proxy...");
            match run_proxy(config, stats, rx).await {
                Ok(_) => native_log("INFO", "run_proxy exited gracefully"),
                Err(e) => native_log("ERROR", &format!("run_proxy exited with error: {:?}", e)),
            }
            native_log("INFO", "Proxy task finished");
        });
        
        native_log("INFO", "Proxy task spawned");

        0
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_getLatency(
        _env: JNIEnv,
        _class: JClass,
    ) -> jint {
        LAST_LATENCY.load(Ordering::Relaxed) as jint
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_getLogs(
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
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_getStats(
        env: JNIEnv,
        _class: JClass,
    ) -> jni::sys::jintArray {
        let stats_opt = GLOBAL_STATS.read().ok().and_then(|g| g.clone());
        let cache_size = GLOBAL_CACHE.read().ok()
            .and_then(|g| g.as_ref().map(|c| c.len()))
            .unwrap_or(0);

        let mut values = [0i32; 10];
        if let Some(stats) = stats_opt {
            values[0] = stats.queries_udp.load(Ordering::Relaxed) as i32;
            values[1] = stats.queries_tcp.load(Ordering::Relaxed) as i32;
            values[2] = stats.malformed.load(Ordering::Relaxed) as i32;
            values[3] = (stats.queries_udp.load(Ordering::Relaxed) + stats.queries_tcp.load(Ordering::Relaxed)) as i32;
            values[4] = stats.queries_https.load(Ordering::Relaxed) as i32;
            values[5] = stats.cache_hits.load(Ordering::Relaxed) as i32;
            values[6] = stats.errors.load(Ordering::Relaxed) as i32;
            let t_lat = stats.total_latency.load(Ordering::Relaxed);
            let count = stats.latency_count.load(Ordering::Relaxed);
            values[7] = if count > 0 { (t_lat / count) as i32 } else { 0 };
            values[8] = stats.cache_misses.load(Ordering::Relaxed) as i32;
            values[9] = cache_size as i32;
        }

        let array = env.new_int_array(10).unwrap();
        env.set_int_array_region(&array, 0, &values).unwrap();
        array.into_raw()
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_clearStats(
        _env: JNIEnv,
        _class: JClass,
    ) {
        if let Some(stats) = GLOBAL_STATS.read().ok().and_then(|g| g.clone()) {
            stats.queries_udp.store(0, Ordering::Relaxed);
            stats.queries_tcp.store(0, Ordering::Relaxed);
            stats.queries_https.store(0, Ordering::Relaxed);
            stats.cache_hits.store(0, Ordering::Relaxed);
            stats.cache_misses.store(0, Ordering::Relaxed);
            stats.malformed.store(0, Ordering::Relaxed);
            stats.errors.store(0, Ordering::Relaxed);
            stats.total_latency.store(0, Ordering::Relaxed);
            stats.latency_count.store(0, Ordering::Relaxed);
            native_log("INFO", "Traffic statistics cleared");
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_stopProxy(
        _env: JNIEnv,
        _class: JClass,
    ) {
        let mut lock = CANCELLATION_TOKEN.lock().unwrap();
        if let Some(token) = lock.take() {
            token.cancel();
        }
        // Signal the native log thread to drain and exit cleanly
        let _ = NATIVE_LOG_SENDER.send(NativeLog::Shutdown);
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_clearCache(
        _env: JNIEnv,
        _class: JClass,
    ) {
        if let Ok(guard) = GLOBAL_CACHE.read() {
            if let Some(cache) = guard.as_ref() {
                cache.invalidate_all();
                native_log("INFO", "DNS Cache cleared successfully");
            } else {
                native_log("WARN", "DNS Cache clear failed: Cache not initialized");
            }
        }
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_io_github_sms1sis_oxidoh_ProxyService_clearLogs(
        _env: JNIEnv,
        _class: JClass,
    ) {
        let mut logs = QUERY_LOGS.lock().unwrap();
        logs.clear();
        native_log("INFO", "Query logs cleared successfully");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_domain_google() {
        // Simple DNS query for google.com
        let data = vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, b'g', b'o', b'o', b'g', b'l', b'e', 
            0x03, b'c', b'o', b'm', 0x00, 
            0x00, 0x01, 0x00, 0x01
        ];
        let domain = extract_domain(&data);
        assert_eq!(domain, "google.com");
    }

    #[test]
    fn test_extract_domain_short() {
        let data = vec![0x00; 12];
        assert_eq!(extract_domain(&data), "unknown");
    }

    #[test]
    fn test_stats_init() {
        let stats = Stats::new();
        assert_eq!(stats.queries_udp.load(Ordering::Relaxed), 0);
        assert_eq!(stats.queries_tcp.load(Ordering::Relaxed), 0);
        assert_eq!(stats.errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_extract_urls() {
        let input = "https://example.com/dns-query https://proxy.com/target";
        let urls = extract_urls(input);
        assert_eq!(urls.len(), 2);
        assert_eq!(urls[0], "https://example.com/dns-query");
        assert_eq!(urls[1], "https://proxy.com/target");
    }
    
    #[test]
    fn test_extract_urls_single() {
        let input = "https://one.com/dns";
        let urls = extract_urls(input);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0], "https://one.com/dns");
    }
}