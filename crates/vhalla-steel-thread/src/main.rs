#![allow(missing_docs)]

fn main() {
    match vhalla_steel_thread::run_once() {
        Ok(receipt) => println!(
            "steel thread complete: event={:?} operation={:?} bytes={}",
            receipt.host.event_id, receipt.host.operation, receipt.delivered_bytes
        ),
        Err(error) => {
            eprintln!("steel thread rejected: {error:?}");
            std::process::exit(1);
        }
    }
}
