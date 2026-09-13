#![forbid(unsafe_code)]
#![allow(missing_docs)]

fn main() {
    #[cfg(unix)]
    if let Err(error) = run() {
        eprintln!("vhalla: {error}");
        std::process::exit(1);
    }
    #[cfg(not(unix))]
    {
        eprintln!("vhalla: native identity custody is currently qualified only on Unix");
        std::process::exit(1);
    }
}

#[cfg(unix)]
fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args_os().skip(1).take(4).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("vhalla (valhalla)\n\nvhalla identity init <new-directory>\nvhalla identity show <existing-directory>\n\nEarly native identity commands; rooms and networking are not connected yet.");
        return Ok(());
    }
    if args.len() != 3 || args[0] != "identity" {
        return Err("usage: vhalla identity <init|show> <directory>".into());
    }
    let identity = if args[1] == "init" {
        vhalla_identity::Identity::create_new(&args[2])
    } else if args[1] == "show" {
        vhalla_identity::Identity::open(&args[2])
    } else {
        return Err("identity command must be init or show".into());
    }
    .map_err(|error| format!("identity operation failed: {error:?}"))?;
    let public = identity
        .public_key()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!("application-key {public}");
    Ok(())
}
