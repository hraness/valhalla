//! Local design review fixture. All keys and labels are synthetic.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
    fs,
    path::PathBuf,
    time::Instant,
};
use vhalla_agent_portraits_spike::{Detail, Portrait, Theme};
fn fixture(n: u64) -> [u8; 32] {
    let mut k = [0; 32];
    k[..8].copy_from_slice(&n.to_be_bytes());
    k
}
fn main() -> std::io::Result<()> {
    let out = PathBuf::from(std::env::args_os().nth(1).expect("output directory"));
    fs::create_dir_all(&out)?;
    let mut html = String::from(include_str!("gallery-head.html"));
    let names = [
        "Moss", "Ember", "Tide", "Orchid", "Ochre", "Glacier", "Coral", "Iris",
    ];
    let mut maximum = 0;
    let mut hashes = BTreeSet::new();
    let mut pictures = BTreeSet::new();
    let mut topologies = BTreeSet::new();
    let mut mono_families = BTreeMap::new();
    for (row, name) in names.iter().enumerate() {
        write!(html,"<section class=\"family\"><div class=\"family-name\"><h2>{name}</h2><p>Owner {}</p></div><div class=\"siblings\">",row+1).unwrap();
        for col in 0..8 {
            let p =
                Portrait::from_public_hints([0; 32], fixture(row as u64 + 1), fixture(100 + col));
            write!(html, "<figure><div class=\"portrait\">").unwrap();
            for (theme, class) in [
                (Theme::Light, "light"),
                (Theme::Dark, "dark"),
                (Theme::Mono, "mono"),
            ] {
                for (detail, dc) in [(Detail::Full, "full"), (Detail::Compact, "compact")] {
                    let svg = p.svg(theme, detail);
                    maximum = maximum.max(svg.len());
                    let file = format!("family-{row}-agent-{col}-{class}-{dc}.svg");
                    fs::write(out.join(&file), &svg)?;
                    write!(html,"<img class=\"{class} {dc}\" width=\"128\" height=\"128\" src=\"{file}\" alt=\"{name} agent {} portrait\">",col+1).unwrap();
                }
            }
            write!(
                html,
                "</div><figcaption>Agent {}</figcaption></figure>",
                col + 1
            )
            .unwrap();
        }
        html.push_str("</div></section>");
    }
    html.push_str("</div><p class=\"note\">Synthetic identities · experimental renderer v0 · artwork does not verify ownership</p></main></body></html>");
    fs::write(out.join("index.html"), html)?;
    fs::write(out.join("gallery.css"), include_str!("gallery.css"))?;
    let start = Instant::now();
    for owner in 1..=64 {
        let family =
            Portrait::from_public_hints([0; 32], fixture(owner), fixture(100)).family_traits();
        *mono_families
            .entry((family.cut, family.emblem))
            .or_insert(0usize) += 1;
        for agent in 100..116 {
            let p = Portrait::from_public_hints([0; 32], fixture(owner), fixture(agent));
            hashes.insert(p.cache_key());
            topologies.insert(p.agent_traits().topology);
            let mut id = String::from("p");
            for b in &p.cache_key()[..16] {
                write!(id, "{b:02x}").unwrap();
            }
            id.push_str("01"); // Light / Full; normalize internal IDs before comparing artwork.
            let svg = p.svg(Theme::Light, Detail::Full);
            maximum = maximum.max(svg.len());
            pictures.insert(svg.replace(&id, "portrait"));
        }
    }
    let elapsed = start.elapsed();
    let mono_pairs: usize = mono_families
        .values()
        .map(|count| count * (count - 1) / 2)
        .sum();
    let mono_max = mono_families.values().max().copied().unwrap_or(0);
    let report=format!("{{\"fixture_count\":1024,\"distinct_cache_keys\":{},\"distinct_normalized_svgs\":{},\"topologies_seen\":{},\"max_svg_bytes\":{},\"compact_mono_possible_family_categories\":48,\"compact_mono_sample_family_categories\":{},\"compact_mono_same_category_owner_pairs\":{},\"compact_mono_max_owners_in_category\":{},\"render_and_compare_ms\":{},\"note\":\"Local fixture sample; distinct SVG source and family-category counts are not perceptual uniqueness or production performance guarantees\"}}\n",hashes.len(),pictures.len(),topologies.len(),maximum,mono_families.len(),mono_pairs,mono_max,elapsed.as_millis());
    fs::write(out.join("sample.json"), &report)?;
    println!("{report}");
    Ok(())
}
