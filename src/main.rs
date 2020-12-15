pub mod config;
pub mod dns_utils;
mod odoh;

use anyhow::Result;
use clap::{App, Arg};
use config::Config;

use crate::odoh::ODOHSession;
use std::env;

const PKG_NAME: &str = env!("CARGO_PKG_NAME");
const PKG_AUTHORS: &str = env!("CARGO_PKG_AUTHORS");
const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

#[tokio::main(core_threads = 1, max_threads = 1)]
async fn main() -> Result<()> {
    let matches = App::new(PKG_NAME)
        .version(PKG_VERSION)
        .author(PKG_AUTHORS)
        .about(PKG_DESCRIPTION)
        .arg(
            Arg::with_name("config_file")
                .short("c")
                .long("config")
                .value_name("FILE")
                .help("Path to the config.toml config file")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("domain")
                .help("Domain to query")
                .required(true)
                .index(1),
        )
        .arg(
            Arg::with_name("type")
                .help("Query type")
                .required(true)
                .index(2),
        )
        .get_matches();

    let config_file = matches
        .value_of("config_file")
        .unwrap_or("tests/config.toml");
    let config = Config::from_path(config_file)?;
    let domain = matches.value_of("domain").unwrap();
    let qtype = matches.value_of("type").unwrap();

    let session = ODOHSession::new(
        config.server.target.as_str(),
        config.server.proxy.as_ref().map(|v| v.as_str()),
    )
    .await?;

    let message = session.resolve(domain, qtype).await?;
    let answers = message.answers();
    if answers.is_empty() {
        println!("No result found for domain {}!", domain)
    } else {
        println!("Domain: {}", domain);
        println!("{} records:", qtype);
        for record in answers {
            println!("\t{}\t{:?}", record.name(), record.rdata())
        }
    }
    Ok(())
}
