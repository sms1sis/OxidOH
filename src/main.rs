use clap::Parser;
use anyhow::Result;
use std::sync::Arc;
use tracing::Level;
use oxidoh::{Config, Stats, run_proxy};

#[derive(Parser, Clone)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Local IPv4/v6 address to bind to
    #[arg(short = 'a', long, default_value = "127.0.0.1")]
    listen_addr: String,

    /// Local port to bind to
    #[arg(short = 'p', long, default_value_t = 5053)]
    listen_port: u16,

    /// Number of TCP clients to serve
    #[arg(short = 'T', long, default_value_t = 20)]
    tcp_client_limit: usize,

    /// Comma-separated IPv4/v6 addresses and ports (addr:port) of DNS servers to resolve resolver host
    #[arg(short = 'b', long, default_value = "1.1.1.1")]
    bootstrap_dns: String,

    /// Optional polling interval of DNS servers
    #[arg(short = 'i', long, default_value_t = 120)]
    polling_interval: u64,

    /// Force IPv4 hostnames for DNS resolvers
    #[arg(short = '4', long)]
    force_ipv4: bool,

    /// The ODoH Target URL
    #[arg(short = 'r', long, default_value = "https://odoh.cloudflare-dns.com/dns-query")]
    odoh_target_url: String,

    /// The ODoH Proxy URL
    #[arg(short = 'x', long)]
    odoh_proxy_url: Option<String>,

    /// Source IPv4/v6 address for outbound HTTPS connections
    #[arg(short = 'S', long)]
    source_addr: Option<String>,

    /// Maximum idle time in seconds allowed for reusing a HTTPS connection
    #[arg(short = 'm', long, default_value_t = 118)]
    max_idle_time: u64,

    /// Time in seconds to tolerate connection timeouts of reused connections
    #[arg(short = 'L', long, default_value_t = 15)]
    conn_loss_time: u64,

    /// Increase logging verbosity
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Optional statistic printout interval
    #[arg(short = 's', long, default_value_t = 0)]
    statistic_interval: u64,

    /// Cache TTL in seconds (default 60)
    #[arg(long, default_value_t = 60)]
    cache_ttl: u64,

    /// Optional domain to exclude from cache
    #[arg(short = 'e', long)]
    exclude_domain: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    setup_logging(args.verbose);

    let config = Config {
        listen_addr: args.listen_addr,
        listen_port: args.listen_port,
        tcp_client_limit: args.tcp_client_limit,
        bootstrap_dns: args.bootstrap_dns,
        polling_interval: args.polling_interval,
        force_ipv4: args.force_ipv4,
        allow_ipv6: !args.force_ipv4,
        odoh_target_url: args.odoh_target_url,
        odoh_proxy_url: args.odoh_proxy_url,
        proxy_server: None,
        source_addr: args.source_addr,
        http11: false,
        http3: false,
        max_idle_time: args.max_idle_time,
        conn_loss_time: args.conn_loss_time,
        ca_path: None,
        statistic_interval: args.statistic_interval,
        cache_ttl: args.cache_ttl,
        exclude_domain: args.exclude_domain,
    };

    let stats = Arc::new(Stats::new());
    let (_shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    run_proxy(config, stats, shutdown_rx).await?;

    Ok(())
}

fn setup_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .init();
}
