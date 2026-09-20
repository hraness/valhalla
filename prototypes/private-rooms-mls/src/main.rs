fn main() {
    match valhalla_private_rooms_mls_qualification::run_qualification() {
        Ok(()) => println!("OpenMLS qualification passed: join, encrypted message, removal."),
        Err(error) => {
            eprintln!("OpenMLS qualification failed: {error}");
            std::process::exit(1);
        }
    }
}
