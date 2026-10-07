#![allow(missing_docs)]

use std::{collections::BTreeSet, convert::TryFrom};

use vhalla_public_sim::{run, Config};

enum CliAction {
    Run(Config),
    Help,
}

fn parse_u64(option: &str, raw: &str) -> Result<u64, String> {
    raw.parse::<u64>()
        .map_err(|_| format!("{option} requires an unsigned integer"))
}

fn parse_usize(option: &str, raw: &str) -> Result<usize, String> {
    let value = parse_u64(option, raw)?;
    usize::try_from(value).map_err(|_| format!("{option} is too large"))
}

fn parse_u8(option: &str, raw: &str) -> Result<u8, String> {
    let value = parse_u64(option, raw)?;
    u8::try_from(value).map_err(|_| format!("{option} is too large"))
}

fn parse_args<I>(args: I) -> Result<CliAction, String>
where
    I: IntoIterator<Item = String>,
{
    let defaults = Config::default();
    let mut config = defaults.clone();
    let mut seen = BTreeSet::new();
    let mut partition_start_explicit = false;
    let mut partition_end_explicit = false;
    let mut no_partition = false;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                if !seen.is_empty() || args.next().is_some() {
                    return Err("--help cannot be combined with other arguments".to_owned());
                }
                return Ok(CliAction::Help);
            }
            "--no-partition" => {
                if partition_start_explicit || partition_end_explicit {
                    return Err(
                        "--no-partition conflicts with an explicit partition interval".to_owned(),
                    );
                }
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --no-partition".to_owned());
                }
                no_partition = true;
                config.partition_start = None;
                config.partition_end = None;
            }
            "--seed" => {
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --seed".to_owned());
                }
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --seed".to_owned())?;
                config.seed = parse_u64("--seed", &raw)?;
            }
            "--peers" => {
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --peers".to_owned());
                }
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --peers".to_owned())?;
                config.peers = parse_usize("--peers", &raw)?;
            }
            "--events" => {
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --events".to_owned());
                }
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --events".to_owned())?;
                config.events = parse_usize("--events", &raw)?;
            }
            "--steps" => {
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --steps".to_owned());
                }
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --steps".to_owned())?;
                config.steps = parse_usize("--steps", &raw)?;
            }
            "--churn-percent" => {
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --churn-percent".to_owned());
                }
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --churn-percent".to_owned())?;
                config.churn_percent = parse_u8("--churn-percent", &raw)?;
            }
            "--partition-start" => {
                if no_partition {
                    return Err("--partition-start conflicts with --no-partition".to_owned());
                }
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --partition-start".to_owned());
                }
                partition_start_explicit = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --partition-start".to_owned())?;
                config.partition_start = Some(parse_usize("--partition-start", &raw)?);
            }
            "--partition-end" => {
                if no_partition {
                    return Err("--partition-end conflicts with --no-partition".to_owned());
                }
                if !seen.insert(arg.clone()) {
                    return Err("duplicate option --partition-end".to_owned());
                }
                partition_end_explicit = true;
                let raw = args
                    .next()
                    .ok_or_else(|| "missing value for --partition-end".to_owned())?;
                config.partition_end = Some(parse_usize("--partition-end", &raw)?);
            }
            _ => return Err(format!("unknown argument `{arg}`")),
        }
    }

    if partition_start_explicit != partition_end_explicit {
        return Err("--partition-start and --partition-end must be provided together".to_owned());
    }
    // The default interval is only enabled when it fits the selected step
    // count. A caller changing either endpoint must provide a valid pair; we
    // never silently clip an explicit interval.
    if !no_partition && !partition_start_explicit && !partition_end_explicit {
        if let Some(end) = defaults.partition_end {
            if end > config.steps {
                config.partition_start = None;
                config.partition_end = None;
            }
        }
    }
    config.validate().map_err(|error| error.to_string())?;
    Ok(CliAction::Run(config))
}

fn print_help() {
    println!(
        "Usage: vhalla-public-sim [OPTIONS]\n\n\
         Options:\n\
           --seed N                 deterministic workload seed\n\
           --peers N                peer count (1..={})\n\
           --events N               generated event count (1..={})\n\
           --steps N                simulation steps (1..={})\n\
           --churn-percent N        per-peer toggle probability (0..=100)\n\
           --partition-start N      inclusive partition step\n\
           --partition-end N        exclusive partition step\n\
           --no-partition           disable the default partition interval\n\
           -h, --help               show this help",
        vhalla_public_sim::MAX_PEERS,
        vhalla_public_sim::MAX_EVENTS,
        vhalla_public_sim::MAX_STEPS,
    );
}

fn main() {
    match parse_args(std::env::args().skip(1)) {
        Ok(CliAction::Help) => print_help(),
        Ok(CliAction::Run(config)) => match run(config) {
            Ok(receipt) => println!("{}", receipt.to_json()),
            Err(error) => {
                eprintln!("simulation refused: {error}");
                std::process::exit(2);
            }
        },
        Err(error) => {
            eprintln!("simulation refused: {error}");
            eprintln!("try --help for valid options");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_config(arguments: &[&str]) -> Result<Config, String> {
        let arguments = arguments.iter().map(|argument| (*argument).to_owned());
        match parse_args(arguments)? {
            CliAction::Run(config) => Ok(config),
            CliAction::Help => Err("help".to_owned()),
        }
    }

    #[test]
    fn parser_is_strict_and_fail_closed() {
        assert!(parse_config(&["--unknown"]).is_err());
        assert!(parse_config(&["--seed"]).is_err());
        assert!(parse_config(&["--seed", "not-a-number"]).is_err());
        assert!(parse_config(&["--seed", "1", "--seed", "2"]).is_err());
        assert!(parse_config(&["--peers", "513"]).is_err());
        assert!(parse_config(&["--churn-percent", "256"]).is_err());
        assert!(parse_config(&["--no-partition", "--partition-start", "1"]).is_err());
        assert!(parse_config(&["--partition-start", "1"]).is_err());
        assert!(parse_config(&["--partition-end", "2"]).is_err());
    }

    #[test]
    fn parser_keeps_explicit_intervals_and_disables_only_the_default() {
        let config = parse_config(&[
            "--seed",
            "7",
            "--peers",
            "4",
            "--events",
            "8",
            "--steps",
            "12",
            "--churn-percent",
            "0",
            "--partition-start",
            "2",
            "--partition-end",
            "5",
        ])
        .unwrap();
        assert_eq!(config.seed, 7);
        assert_eq!(config.partition_start, Some(2));
        assert_eq!(config.partition_end, Some(5));

        let config = parse_config(&["--steps", "10"]).unwrap();
        assert_eq!(config.partition_start, None);
        assert_eq!(config.partition_end, None);

        let config = parse_config(&["--no-partition"]).unwrap();
        assert_eq!(config.partition_start, None);
        assert_eq!(config.partition_end, None);
    }

    #[test]
    fn help_cannot_hide_other_arguments() {
        assert!(matches!(
            parse_args(vec!["--help".to_owned()]),
            Ok(CliAction::Help)
        ));
        assert!(parse_args(vec!["--help".to_owned(), "--seed".to_owned()]).is_err());
        assert!(parse_args(vec![
            "--seed".to_owned(),
            "1".to_owned(),
            "--help".to_owned(),
        ])
        .is_err());
    }
}
