
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use clap::{App, AppSettings, Arg};
use rayon::prelude::*;
use rayon::ThreadPoolBuilder;

use wireguard_vanity_lib::trial;

const BENCHMARK_SECONDS: u64 = 10;
const BATCH_SIZE: u64 = 10_000;

#[derive(Debug)]
struct ParseError(String);

impl Error for ParseError {}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn format_time(seconds: f64) -> String {
    if seconds >= 86400.0 {
        format!("{:.2} days", seconds / 86400.0)
    } else if seconds >= 3600.0 {
        format!("{:.2} hours", seconds / 3600.0)
    } else if seconds >= 60.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds >= 1.0 {
        format!("{:.1} seconds", seconds)
    } else if seconds >= 1e-3 {
        format!("{:.1} ms", seconds * 1e3)
    } else if seconds >= 1e-6 {
        format!("{:.1} us", seconds * 1e6)
    } else {
        format!("{:.1} ns", seconds * 1e9)
    }
}

fn benchmark(
    targets: &[String],
    end: Option<usize>,
    case_sensitive: bool,
) -> (u64, Duration) {
    let start = Instant::now();
    let mut attempts = 0u64;

    while start.elapsed() < Duration::from_secs(BENCHMARK_SECONDS) {
        (0..BATCH_SIZE)
            .into_par_iter()
            .for_each(|_| {
                let _ = trial(targets, end, case_sensitive);
            });

        attempts += BATCH_SIZE;
    }

    (attempts, start.elapsed())
}

fn print_match(
    result: (String, String, Vec<usize>),
    targets: &[String],
) -> Result<(), io::Error> {
    let (private_b64, public_b64, matched) = result;

    let names: Vec<&str> = matched
        .iter()
        .map(|&index| targets[index].as_str())
        .collect();

    writeln!(
        io::stdout(),
        "match {}  private {}  public {}",
        names.join(","),
        private_b64,
        public_b64
    )
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("wireguard-vanity-address")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version(env!("CARGO_PKG_VERSION"))
        .author("Brian Warner <warner@lothar.com>")
        .about("Find WireGuard keypairs matching one or more public-key strings")
        .arg(
            Arg::with_name("RANGE")
                .long("in")
                .takes_value(true)
                .help("search within the first RANGE characters (default: prefix only)"),
        )
        .arg(
            Arg::with_name("THREADS")
                .long("threads")
                .takes_value(true)
                .help("number of worker threads (default: all available cores)"),
        )
        .arg(
            Arg::with_name("CASE_SENSITIVE")
                .long("case-sensitive")
                .help("match target strings with exact capitalisation"),
        )
        .arg(
            Arg::with_name("TARGETS")
                .required(true)
                .multiple(true)
                .help("one or more strings to find in public keys"),
        )
        .get_matches();

    let case_sensitive = matches.is_present("CASE_SENSITIVE");

    let targets: Vec<String> = matches
        .values_of("TARGETS")
        .unwrap()
        .map(str::to_string)
        .collect();

    for target in &targets {
        if !target.is_ascii() {
            return Err(ParseError(
                format!("target '{}' must contain ASCII characters only", target)
            ).into());
        }

        if target.is_empty() {
            return Err(ParseError("targets must not be empty".into()).into());
        }

        if !target.bytes().all(|b| {
            b.is_ascii_alphanumeric() || b == b'+' || b == b'/'
        }) {
            return Err(ParseError(
                format!("target '{}' contains invalid Base64 characters", target)
            ).into());
        }
    }

    let end: Option<usize> = match matches.value_of("RANGE") {
        Some(value) => {
            let range: usize = value.parse()?;

            if range == 0 || range > 43 {
                return Err(ParseError(
                    "search range must be between 1 and 43".into()
                ).into());
            }

            for target in &targets {
                if target.len() > range {
                    return Err(ParseError(
                        format!(
                            "target '{}' is longer than search range {}",
                            target, range
                        )
                    ).into());
                }
            }

            Some(range)
        }
        None => None,
    };

    let threads: usize = match matches.value_of("THREADS") {
        Some(value) => value.parse()?,
        None => num_cpus::get(),
    };

    if threads == 0 {
        return Err(ParseError(
            "thread count must be at least 1".into()
        ).into());
    }

    ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()?;

    let search_targets: Vec<String> = if case_sensitive {
        targets.clone()
    } else {
        targets.iter()
            .map(|target| target.to_ascii_lowercase())
            .collect()
    };

    println!(
        "searching for {} target(s), {}",
        targets.len(),
        if case_sensitive {
            "case-sensitive"
        } else {
            "case-insensitive"
        }
    );

    for target in &targets {
        let offsets = match end {
            Some(range) => range - target.len() + 1,
            None => 1,
        };

        let mut combinations = 1.0f64;

        for c in target.chars() {
            let choices = if !case_sensitive && c.is_ascii_alphabetic() {
                2.0
            } else {
                1.0
            };

            combinations *= 64.0 / choices;
        }

        let trials_per_key = combinations / offsets as f64;

        println!(
            "  {:<12}  1 in {:.0}  ({} position{})",
            target,
            trials_per_key,
            offsets,
            if offsets == 1 { "" } else { "s" }
        );
    }

    println!(
        "benchmarking ({} seconds, {} worker threads)...",
        BENCHMARK_SECONDS, threads
    );
    io::stdout().flush()?;

    let (attempts, elapsed) =
        benchmark(&search_targets, end, case_sensitive);

    let trials_per_second =
        attempts as f64 / elapsed.as_secs_f64();

    println!(
        "benchmark: {} trials in {}",
        attempts,
        format_time(elapsed.as_secs_f64())
    );

    println!(
        "performance: {:.0} trials/s",
        trials_per_second
    );


    println!();

    println!(
        "{:<12}  {:<20}  {}",
        "Target", "Probability", "Expected time"
    );

    for target in &targets {
        let offsets = match end {
            Some(range) => range - target.len() + 1,
            None => 1,
        };

        let mut combinations = 1.0f64;

        for c in target.chars() {
            let choices = if !case_sensitive && c.is_ascii_alphabetic() {
                2.0
            } else {
                1.0
            };

            combinations *= 64.0 / choices;
        }

        let trials_per_key = combinations / offsets as f64;
        let seconds_per_key = trials_per_key / trials_per_second;

        println!(
            "{:<12}  1 in {:<15.0}  {}",
            target,
            trials_per_key,
            format_time(seconds_per_key)
        );
    }

    println!();


    println!("hit Ctrl-C to stop");

    loop {
        (0..1_000_000u64)
            .into_par_iter()
            .map(|_| trial(&search_targets, end, case_sensitive))
            .filter_map(|result| result)
            .try_for_each(|result| print_match(result, &targets))?;
    }
}

