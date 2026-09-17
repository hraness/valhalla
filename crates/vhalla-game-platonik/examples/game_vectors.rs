//! Writes the six `Replay`-kind game manifest vectors into `tests/vectors/`.
//! Run: `cargo run -p vhalla-game-platonik --example game_vectors --features oracle`.

use std::fs;
use std::path::Path;

use vhalla_game_platonik::oracle::convert::convert;
use vhalla_game_platonik::oracle::corpus::replay_manifest;
use vhalla_game_platonik::wire::encode_game_manifest;
use vhalla_witness::vectors::hex;

fn main() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    fs::create_dir_all(&dir).unwrap();
    for name in platonik_core::fixtures::names() {
        let converted = convert(&platonik_core::fixtures::experiment(name).unwrap()).unwrap();
        let manifest = replay_manifest(&converted, [11; 32]);
        let text = format!(
            "id: {name}\nmanifest: {}\nmanifest_hash: {}\nworld_digest: {}\nexperiment: {}\nloading_work: {}\n",
            hex(&encode_game_manifest(&manifest)),
            hex(&manifest.hash().0),
            hex(&manifest.world.0),
            converted.experiment.render(),
            converted.loading_work
        );
        fs::write(dir.join(format!("game-v1-{name}.txt")), text).unwrap();
        println!("{name}: {}", converted.experiment.render());
    }
}
