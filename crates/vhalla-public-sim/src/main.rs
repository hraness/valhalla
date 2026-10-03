#![allow(missing_docs)]

use vhalla_public_sim::{run, Config};

fn value(args: &[String], name: &str, default: u64) -> u64 {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .and_then(|pair| pair[1].parse().ok())
        .unwrap_or(default)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let defaults = Config::default();
    let partition = defaults
        .partition_end
        .filter(|end| *end <= value(&args, "--steps", defaults.steps as u64) as usize)
        .and(defaults.partition_start);
    let config = Config {
        seed: value(&args, "--seed", defaults.seed),
        peers: value(&args, "--peers", defaults.peers as u64) as usize,
        events: value(&args, "--events", defaults.events as u64) as usize,
        steps: value(&args, "--steps", defaults.steps as u64) as usize,
        churn_percent: value(&args, "--churn-percent", defaults.churn_percent as u64) as u8,
        partition_start: partition,
        partition_end: partition.map(|_| defaults.partition_end.unwrap()),
    };
    match run(config) {
        Ok(receipt) => println!("{}", receipt.to_json()),
        Err(error) => {
            eprintln!("simulation refused: {error}");
            std::process::exit(2);
        }
    }
}
