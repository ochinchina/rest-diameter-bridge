use clap::Parser;
use std::str::FromStr;

use log::info;
use rest_diameter_bridge::{
    config::load_stack_configs, metrics::register_metrics, stack::DiameterStack,
};

#[derive(Parser, Debug, Clone)]
#[command(about, long_about=None)]
struct Args {
    #[arg(short, long)]
    config_file: String,
    #[arg(long)]
    log_file: Option<String>,
    #[arg(long)]
    log_level: Option<String>,
    #[arg(long)]
    log_format: Option<String>,
}
fn init_logger(filename: Option<String>, log_level: Option<String>, log_format: Option<String>) {
    let format = log_format.unwrap_or_else(|| "text".to_string());
    let log_level = log_level.unwrap_or_else(|| "info".to_string());

    if format.to_lowercase() == "json" {
        use tracing_subscriber::{EnvFilter, fmt};
        let filter = EnvFilter::try_new(&log_level).unwrap_or_else(|_| EnvFilter::new("info"));

        let builder = fmt()
            .with_env_filter(filter)
            .with_timer(fmt::time::SystemTime::default())
            .json();

        if let Some(filename) = filename {
            let file = std::fs::File::create(filename).unwrap();
            builder.with_writer(file).init();
        } else {
            builder.init();
        }
        tracing_log::LogTracer::init().unwrap();
    } else {
        let log_level = log::LevelFilter::from_str(&log_level).unwrap_or(log::LevelFilter::Info);
        use simplelog::{ConfigBuilder, SimpleLogger, WriteLogger};
        let config = ConfigBuilder::new().set_time_format_rfc3339().build();
        if let Some(filename) = filename {
            let file = std::fs::File::create(filename).unwrap();
            WriteLogger::init(log_level, config, file).unwrap();
        } else {
            SimpleLogger::init(log_level, config).unwrap();
        }
    }
}
#[tokio::main]
async fn main() {
    let args = Args::parse();

    init_logger(args.log_file, args.log_level, args.log_format);
    register_metrics();
    let configs = load_stack_configs(&args.config_file);

    info!("Loaded stack configurations: {:?}", configs);

    if let Ok(configs) = configs {
        configs.into_iter().for_each(|config| {
            let config = config.clone();
            tokio::spawn(async move {
                info!("Starting Diameter stack with config: {:?}", config);
                let mut stack = DiameterStack::new(config);
                stack.start().await;
            });
        });
    }
    tokio::signal::ctrl_c().await.unwrap();
}
