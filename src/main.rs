use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tang::{
    keys::KeyManager,
    security::SecurityConfig,
    server_secure::create_secure_router,
};
use tracing::{info, warn, Level};
use tracing_subscriber;

#[derive(Parser)]
#[command(name = "tang")]
#[command(about = "Tang - Network-Based Cryptographic Binding Server", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Tang server
    Serve(ServeArgs),
    /// Generate new keys
    Keygen(KeygenArgs),
    /// List all keys
    List(ListArgs),
    /// Hide a key (for key rotation)
    Hide(HideArgs),
}

#[derive(Args)]
struct ServeArgs {
    /// Path to the key database directory
    #[arg(short = 'd', long, default_value = "/var/db/tang")]
    db_path: PathBuf,

    /// Port to listen on
    #[arg(short = 'p', long, default_value = "9090")]
    port: u16,

    /// Host to bind to
    #[arg(long, default_value = "0.0.0.0")]
    host: String,

    /// Enable TLS/HTTPS
    #[arg(long)]
    tls: bool,

    /// Path to TLS certificate (PEM format)
    #[arg(long, requires = "tls")]
    tls_cert: Option<PathBuf>,

    /// Path to TLS private key (PEM format)
    #[arg(long, requires = "tls")]
    tls_key: Option<PathBuf>,

    /// Use secure production defaults (stricter limits, timeouts)
    #[arg(long)]
    secure: bool,

    /// Rate limit: requests per second per IP
    #[arg(long)]
    rate_limit: Option<u32>,

    /// Maximum request body size in bytes
    #[arg(long)]
    max_body_size: Option<usize>,
}

#[derive(Args)]
struct KeygenArgs {
    /// Path to the key database directory
    #[arg(short = 'd', long, default_value = "/var/db/tang")]
    db_path: PathBuf,

    /// Generate signing key (default is exchange key)
    #[arg(short = 's', long)]
    signing: bool,
}

#[derive(Args)]
struct ListArgs {
    /// Path to the key database directory
    #[arg(short = 'd', long, default_value = "/var/db/tang")]
    db_path: PathBuf,

    /// Show hidden keys
    #[arg(short = 'a', long)]
    all: bool,
}

#[derive(Args)]
struct HideArgs {
    /// Path to the key database directory
    #[arg(short = 'd', long, default_value = "/var/db/tang")]
    db_path: PathBuf,

    /// Key ID to hide
    kid: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .with_target(false)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Serve(args) => serve(args).await?,
        Commands::Keygen(args) => keygen(args)?,
        Commands::List(args) => list(args)?,
        Commands::Hide(args) => hide(args)?,
    }

    Ok(())
}

async fn serve(args: ServeArgs) -> anyhow::Result<()> {
    info!("Starting Tang server with enhanced security");
    info!("Database path: {}", args.db_path.display());
    info!("Listening on {}:{}", args.host, args.port);

    // Create security configuration
    let mut security_config = if args.secure {
        info!("Using secure production defaults");
        SecurityConfig::secure()
    } else {
        SecurityConfig::default()
    };

    // Apply custom overrides
    if let Some(rate_limit) = args.rate_limit {
        security_config.rate_limit_per_second = rate_limit;
        info!("Custom rate limit: {} req/sec", rate_limit);
    }

    if let Some(max_body_size) = args.max_body_size {
        security_config.max_body_size = max_body_size;
        info!("Custom max body size: {} bytes", max_body_size);
    }

    // TLS configuration
    if args.tls {
        security_config.enable_tls = true;
        security_config.tls_cert_path = args.tls_cert.map(|p| p.to_string_lossy().to_string());
        security_config.tls_key_path = args.tls_key.map(|p| p.to_string_lossy().to_string());

        if security_config.tls_cert_path.is_none() || security_config.tls_key_path.is_none() {
            return Err(anyhow::anyhow!(
                "TLS enabled but certificate or key path not provided"
            ));
        }

        info!("TLS/HTTPS enabled");
    } else {
        warn!("TLS/HTTPS is DISABLED - use --tls for production!");
    }

    // Validate configuration
    security_config.validate()?;

    info!("Security configuration:");
    info!("  Max body size: {} bytes", security_config.max_body_size);
    info!("  Request timeout: {:?}", security_config.request_timeout);
    info!("  Rate limit: {} req/sec (burst: {})",
        security_config.rate_limit_per_second,
        security_config.rate_limit_burst
    );

    let key_manager = Arc::new(KeyManager::new(&args.db_path)?);

    // Check if we have any keys
    let active_keys = key_manager.load_active_keys()?;
    if active_keys.keys.is_empty() {
        info!("No keys found in database. Generating initial keys...");
        let sig_kid = key_manager.generate_signing_key()?;
        let exc_kid = key_manager.generate_exchange_key()?;
        info!("Generated signing key: {}", sig_kid);
        info!("Generated exchange key: {}", exc_kid);
    } else {
        info!("Loaded {} active keys", active_keys.keys.len());
    }

    let app = create_secure_router(key_manager, security_config.clone());

    let addr = format!("{}:{}", args.host, args.port);

    info!("Tang server ready and listening");

    if security_config.enable_tls {
        // TLS support
        info!("Starting HTTPS server");
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            security_config.tls_cert_path.as_ref().unwrap(),
            security_config.tls_key_path.as_ref().unwrap(),
        )
        .await?;

        axum_server::bind_rustls(addr.parse()?, config)
            .serve(app.into_make_service())
            .await?;
    } else {
        // Plain HTTP
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        axum::serve(listener, app).await?;
    }

    Ok(())
}

fn keygen(args: KeygenArgs) -> anyhow::Result<()> {
    let key_manager = KeyManager::new(&args.db_path)?;

    let kid = if args.signing {
        info!("Generating signing key...");
        key_manager.generate_signing_key()?
    } else {
        info!("Generating exchange key...");
        key_manager.generate_exchange_key()?
    };

    println!("Generated key with ID: {}", kid);
    println!("Key saved to: {}", args.db_path.display());

    Ok(())
}

fn list(args: ListArgs) -> anyhow::Result<()> {
    let key_manager = KeyManager::new(&args.db_path)?;

    if args.all {
        println!("Listing all keys (including hidden) in: {}", args.db_path.display());
        // TODO: Implement listing hidden keys
        println!("(Hidden keys listing not yet implemented)");
    } else {
        println!("Listing active keys in: {}", args.db_path.display());
    }

    let keys = key_manager.load_active_keys()?;

    if keys.keys.is_empty() {
        println!("No keys found.");
        return Ok(());
    }

    for key in keys.keys {
        let kid = key
            .other
            .get("kid")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let use_type = key
            .other
            .get("use")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");

        println!("  {} - {} ({})", kid, use_type, key.kty);
    }

    Ok(())
}

fn hide(args: HideArgs) -> anyhow::Result<()> {
    let key_manager = KeyManager::new(&args.db_path)?;

    info!("Hiding key: {}", args.kid);
    key_manager.hide_key(&args.kid)?;

    println!("Key {} has been hidden", args.kid);
    println!("It will no longer be advertised but can still be used for recovery");

    Ok(())
}
