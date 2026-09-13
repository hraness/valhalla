#![no_std]
#![forbid(unsafe_code)]
//! Experimental, deterministic artwork. These inputs assert no identity or ownership.
//! Render as an image; verify affiliations and show their status outside the artwork.
extern crate alloc;
use alloc::{format, string::String, vec::Vec};
use core::fmt::Write;
use sha2::{Digest, Sha256};

pub const VERSION: u8 = 0;
pub const MAX_SVG_BYTES: usize = 32_768;
pub const MAX_ATOMS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Theme {
    Light,
    Dark,
    Mono,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detail {
    Compact,
    Full,
}

/// Public display inputs, never a verified membership or permission capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Portrait {
    family: [u8; 32],
    individual: [u8; 32],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FamilyTraits {
    pub hue: u16,
    pub material: u8,
    pub cut: u8,
    pub emblem: u8,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentTraits {
    pub topology: u8,
    pub count: u8,
    pub turn: u16,
    pub reach: u8,
    pub width: u8,
    pub core: u8,
}

fn derive(domain: &[u8], parts: &[[u8; 32]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"vhalla/portrait/");
    h.update([VERSION]);
    h.update(domain);
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}
impl Portrait {
    /// Scope is explicit; public scope does not make reused public keys unlinkable.
    /// `owner_hint` must be admitted by a separate affiliation policy in a real UI.
    pub fn from_public_hints(scope: [u8; 32], owner_hint: [u8; 32], agent: [u8; 32]) -> Self {
        Self {
            family: derive(b"family", &[scope, owner_hint]),
            individual: derive(b"individual", &[scope, owner_hint, agent]),
        }
    }
    pub fn family_traits(&self) -> FamilyTraits {
        FamilyTraits {
            hue: u16::from_be_bytes([self.family[0], self.family[1]]) % 360,
            material: self.family[2] % 6,
            cut: self.family[3] % 6,
            emblem: self.family[4] % 8,
        }
    }
    pub fn agent_traits(&self) -> AgentTraits {
        AgentTraits {
            topology: self.individual[0] % 16,
            count: 3 + self.individual[1] % 5,
            turn: u16::from(self.individual[2] % 24) * 15,
            reach: 25 + self.individual[3] % 13,
            width: 10 + self.individual[4] % 8,
            core: self.individual[5] % 4,
        }
    }
    /// Fixed-size versioned identity for this descriptor, not a security fingerprint.
    pub fn cache_key(&self) -> [u8; 32] {
        derive(b"cache", &[self.family, self.individual])
    }
    pub fn svg(&self, theme: Theme, detail: Detail) -> String {
        let f = self.family_traits();
        let a = self.agent_traits();
        let mut id = String::from("p");
        // Namespacing makes many inline fixture SVGs independent. Prefer <img> in apps.
        for b in &self.cache_key()[..16] {
            write!(id, "{b:02x}").unwrap();
        }
        write!(id, "{}{}", theme as u8, detail as u8).unwrap();
        let hue = f.hue;
        let secondary = (hue + 24 + u16::from(self.family[5] % 37)) % 360;
        let (high, base, low, ink) = match theme {
            Theme::Light => (
                format!("hsl({hue} 75% 78%)"),
                format!("hsl({hue} 64% 53%)"),
                format!("hsl({secondary} 58% 36%)"),
                format!("hsl({hue} 55% 22%)"),
            ),
            Theme::Dark => (
                format!("hsl({hue} 82% 84%)"),
                format!("hsl({hue} 70% 65%)"),
                format!("hsl({secondary} 60% 43%)"),
                format!("hsl({hue} 65% 28%)"),
            ),
            Theme::Mono => (
                String::from("#f4f4f4"),
                String::from("#aaaaaa"),
                String::from("#737373"),
                String::from("#333333"),
            ),
        };
        let mut s = format!("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 128 128\" width=\"128\" height=\"128\"><defs><linearGradient id=\"{id}g\" x1=\"0\" y1=\"0\" x2=\"1\" y2=\"1\"><stop offset=\"0\" stop-color=\"{high}\"/><stop offset=\"0.55\" stop-color=\"{base}\"/><stop offset=\"1\" stop-color=\"{low}\"/></linearGradient>");
        if detail == Detail::Full {
            write!(s, "<pattern id=\"{id}w\" width=\"16\" height=\"16\" patternUnits=\"userSpaceOnUse\" fill=\"none\" stroke=\"{ink}\" stroke-width=\"1.5\" opacity=\"0.24\">").unwrap();
            s.push_str(match f.material {
                0 => "<path d=\"M0 4H16M0 12H16\"/>",
                1 => "<path d=\"M-4 4L4 -4M0 16L16 0M12 20L20 12\"/>",
                2 => "<circle cx=\"4\" cy=\"4\" r=\"1.5\"/><circle cx=\"12\" cy=\"12\" r=\"1.5\"/>",
                3 => "<path d=\"M0 4L8 10L16 4M0 12L8 18L16 12\"/>",
                4 => "<path d=\"M0 8H16M8 0V16\"/>",
                _ => "<path d=\"M-8 8Q0 -8 8 8T24 8M-8 16Q0 0 8 16T24 16\"/>",
            });
            s.push_str("</pattern>");
        }
        s.push_str("</defs>");
        let atoms = layout(a);
        let (cx, cy, span) = layout_bounds(&atoms);
        let scale = 116_000 / span;
        write!(
            s,
            "<g transform=\"translate(64 64) scale({}.{:03}) translate(-{cx} -{cy})\">",
            scale / 1000,
            scale % 1000
        )
        .unwrap();
        assert!(
            atoms.len() <= MAX_ATOMS,
            "fixed portrait grammar atom limit"
        );
        for (i, atom) in atoms.iter().enumerate() {
            let path = cut_path(f.cut, atom.w, atom.h);
            write!(s, "<g transform=\"translate({} {}) rotate({})\"><path d=\"{path}\" fill=\"url(#{id}g)\" stroke=\"{ink}\" stroke-width=\"1.7\" stroke-linejoin=\"round\"/>", atom.x, atom.y, atom.turn).unwrap();
            if detail == Detail::Full {
                write!(s, "<path d=\"{path}\" fill=\"url(#{id}w)\"/>").unwrap();
                write!(s,"<path d=\"M{} {}Q0 {} {} {}\" fill=\"none\" stroke=\"{high}\" stroke-width=\"2\" opacity=\"0.8\" stroke-linecap=\"round\"/>", -atom.w/2, -atom.h/3, -atom.h+5, atom.w/2, -atom.h/3).unwrap();
            }
            if i % 2 == 0 && detail == Detail::Full {
                write!(s, "<path d=\"M0 {}L0 {}\" fill=\"none\" stroke=\"{ink}\" stroke-width=\"1\" opacity=\"0.32\"/>", -atom.h+5, atom.h-5).unwrap();
            }
            s.push_str("</g>");
        }
        // A repeated owner glyph remains visible when microtexture is omitted.
        let radius = 10 + i16::from(a.core);
        write!(s,"<circle cx=\"64\" cy=\"64\" r=\"{radius}\" fill=\"{ink}\" stroke=\"{high}\" stroke-width=\"1.8\"/><g transform=\"translate(64 64)\" fill=\"none\" stroke=\"{high}\" stroke-width=\"2.5\" stroke-linecap=\"round\" stroke-linejoin=\"round\">").unwrap();
        s.push_str(match f.emblem {
            0 => "<path d=\"M-5 0H5M0 -5V5\"/>",
            1 => "<path d=\"M-5 3L0 -4L5 3\"/>",
            2 => "<path d=\"M-4 -4V4M4 -4V4\"/>",
            3 => "<circle r=\"4.5\"/>",
            4 => "<path d=\"M-5 -3L0 4L5 -3\"/>",
            5 => "<path d=\"M-5 0L0 -5L5 0L0 5Z\"/>",
            6 => "<path d=\"M-5 -3H5M-5 3H5\"/>",
            _ => "<path d=\"M-5 4L0 -4L5 4M-3 1H3\"/>",
        });
        s.push_str("</g></g></svg>");
        assert!(
            s.len() <= MAX_SVG_BYTES,
            "fixed portrait grammar output limit"
        );
        s
    }
}

#[derive(Clone, Copy)]
struct Atom {
    x: i16,
    y: i16,
    w: i16,
    h: i16,
    turn: i16,
}
fn atom(x: i16, y: i16, w: i16, h: i16, turn: i16) -> Atom {
    Atom { x, y, w, h, turn }
}
// Integer unit circle: canonical bytes without platform floating-point/trigonometry.
const CIRCLE: [(i16, i16); 24] = [
    (1000, 0),
    (966, 259),
    (866, 500),
    (707, 707),
    (500, 866),
    (259, 966),
    (0, 1000),
    (-259, 966),
    (-500, 866),
    (-707, 707),
    (-866, 500),
    (-966, 259),
    (-1000, 0),
    (-966, -259),
    (-866, -500),
    (-707, -707),
    (-500, -866),
    (-259, -966),
    (0, -1000),
    (259, -966),
    (500, -866),
    (707, -707),
    (866, -500),
    (966, -259),
];
fn polar(index: usize, radius: i16) -> (i16, i16) {
    let (x, y) = CIRCLE[index % 24];
    (
        (i32::from(x) * i32::from(radius) / 1000) as i16,
        (i32::from(y) * i32::from(radius) / 1000) as i16,
    )
}
fn layout(a: AgentTraits) -> Vec<Atom> {
    let mut v = Vec::with_capacity(MAX_ATOMS);
    let n = usize::from(a.count);
    let w = i16::from(a.width);
    let r = i16::from(a.reach);
    let turn = a.turn as i16;
    match a.topology {
        0 => {
            for i in 0..n {
                let k = i * 24 / n;
                let (x, y) = polar(k, r - 10);
                v.push(atom(64 + x, 64 + y, w, 23, k as i16 * 15 + 90 + turn % 45));
            }
        } // corolla
        1 => {
            for i in 0..n {
                let k = 15 + i * 14 / n;
                let (x, y) = polar(k, r - 5);
                v.push(atom(64 + x, 72 + y, w, 22, k as i16 * 15 + 90));
            }
        } // fan
        2 => {
            for i in 0..n {
                let k = i * 24 / n;
                let (x, y) = polar(k, r - 4);
                v.push(atom(64 + x, 64 + y, 10, w + 5, k as i16 * 15 + 35));
            }
        } // pinwheel
        3 => {
            for j in 0..3 {
                for side in [-1, 1] {
                    v.push(atom(
                        64 + side * (19 + j * 5),
                        48 + j * 15,
                        w,
                        22 - j * 3,
                        side * (35 + j * 15),
                    ));
                }
            }
        } // bifold
        4 => {
            for i in 0..4 {
                v.push(atom(
                    46 + (i % 2) * 32,
                    45 + (i / 2) * 36,
                    w + 1,
                    23,
                    if i % 2 == 0 { 40 } else { -40 },
                ));
            }
        } // knot
        5 => {
            for i in 0..n {
                let k = 3 + i * 18 / n;
                let (x, y) = polar(k, r);
                v.push(atom(64 + x, 64 + y, w - 3, 16, k as i16 * 15));
            }
        } // crescent
        6 => {
            for j in 0..3 {
                v.push(atom(64, 40 + j * 24, 25 - j * 4, 13, turn % 30));
            }
        } // cairn
        7 => {
            for side in [-1, 1] {
                v.push(atom(64 + side * 21, 55, 12, 31, side * 28));
                v.push(atom(64 + side * 29, 35, 10, 16, side * 54));
            }
            v.push(atom(64, 88, w, 19, 0));
        } // coral
        8 => {
            for i in 0..n {
                let k = i * 24 / n;
                let (x, y) = polar(k, r);
                v.push(atom(64 + x, 64 + y, w - 2, 14, k as i16 * 15 + turn));
            }
        } // constellation
        9 => {
            for i in 0..3 {
                for j in 0..3 {
                    if (i + j) % 2 == 0 {
                        v.push(atom(36 + i * 28, 36 + j * 28, w - 1, w - 1, 45));
                    }
                }
            }
        } // lattice
        10 => {
            for i in 0..3 {
                v.push(atom(39 + i * 25, 58 - (i % 2) * 13, 12, 29, (i - 1) * 25));
            }
            v.push(atom(64, 84, 28, 10, 0));
        } // crown
        11 => {
            v.push(atom(67, 58, 25, 30, -35));
            for i in 0..3 {
                v.push(atom(33 + i * 12, 82 + i * 6, 7, 18, -48));
            }
        } // comet
        12 => {
            for i in 0..4 {
                v.push(atom(42 + i * 14, 75 - i * 11, w - 2, 25, -33));
            }
        } // folded ribbon
        13 => {
            v.push(atom(64, 51, 18, 31, 0));
            for side in [-1, 1] {
                v.push(atom(64 + side * 23, 76, 18, 24, side * 52));
            }
        } // trifid
        14 => {
            for i in 0..n {
                let k = i * 24 / n;
                let (x, y) = polar(k, 22);
                v.push(atom(64 + x, 64 + y, 8, 29, k as i16 * 15));
            }
        } // weave
        _ => {
            v.push(atom(64, 64, 23, 34, turn % 90));
            for side in [-1, 1] {
                v.push(atom(64 + side * 31, 58, 8, 23, side * 22));
                v.push(atom(64 + side * 22, 92, 9, 12, side * 35));
            }
        } // seed + satellites
    }
    let (cos, sin) = CIRCLE[usize::from(a.turn / 15)];
    for node in &mut v {
        let x = i32::from(node.x - 64);
        let y = i32::from(node.y - 64);
        node.x = 64 + ((x * i32::from(cos) - y * i32::from(sin)) * 78 / 100_000) as i16;
        node.y = 64 + ((x * i32::from(sin) + y * i32::from(cos)) * 78 / 100_000) as i16;
        node.w = node.w * 78 / 100;
        node.h = node.h * (70 + i16::from(a.reach) - 25) / 100;
        node.turn += a.turn as i16;
    }
    v
}
// Conservative integer bounds include the largest owner core and stroke clearance.
// Maxima of adjacent 15-degree samples bound |sin|/|cos| between those samples.
fn layout_bounds(atoms: &[Atom]) -> (i32, i32, i32) {
    let (mut left, mut top, mut right, mut bottom) = (49, 49, 79, 79);
    for a in atoms {
        let k = a.turn.rem_euclid(360) as usize / 15;
        let (c0, s0) = CIRCLE[k];
        let (c1, s1) = CIRCLE[(k + 1) % 24];
        let c = i32::from(c0.abs().max(c1.abs())) + 1;
        let s = i32::from(s0.abs().max(s1.abs())) + 1;
        let dx = (i32::from(a.w) * c + i32::from(a.h) * s + 999) / 1000 + 2;
        let dy = (i32::from(a.w) * s + i32::from(a.h) * c + 999) / 1000 + 2;
        left = left.min(i32::from(a.x) - dx);
        right = right.max(i32::from(a.x) + dx);
        top = top.min(i32::from(a.y) - dy);
        bottom = bottom.max(i32::from(a.y) + dy);
    }
    (
        (left + right) / 2,
        (top + bottom) / 2,
        (right - left).max(bottom - top) + 2,
    )
}

fn cut_path(cut: u8, w: i16, h: i16) -> String {
    match cut {
        0=>format!("M0 -{h}C{w} -{h} {w} {h} 0 {h}C-{} {h} -{w} -{h} 0 -{h}Z",w),
        1=>format!("M0 -{h}Q{w} -{} {w} 0Q{w} {} 0 {h}Q-{w} {} -{w} 0Q-{w} -{} 0 -{h}Z",h/2,h/2,h/2,h/2),
        2=>format!("M0 -{h}L{w} -{}L{} {h}H-{}L-{w} -{}Z",h/3,w/2,w/2,h/3),
        3=>format!("M-{} -{h}H{}Q{w} -{h} {w} -{}V{}Q{w} {h} {} {h}H-{}Q-{w} {h} -{w} {}V-{}Q-{w} -{h} -{} -{h}Z",w/2,w/2,h/2,h/2,w/2,w/2,h/2,h/2,w/2),
        4=>format!("M0 -{h}C{w} -{h} {w} 0 {} {}L0 {h}L-{} {}C-{w} 0 -{w} -{h} 0 -{h}Z",w/2,h/3,w/2,h/3),
        _=>format!("M0 -{h}L{w} 0L0 {h}L-{w} 0Z"),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn bounded_deterministic(scope in any_array(),owner in any_array(),agent in any_array()) {
            let p=Portrait::from_public_hints(scope,owner,agent);
            for theme in [Theme::Light,Theme::Dark,Theme::Mono] {
                for detail in [Detail::Full,Detail::Compact] {
                    let s=p.svg(theme,detail);
                    prop_assert_eq!(&s,&p.svg(theme,detail));
                    prop_assert!(s.len()<=MAX_SVG_BYTES);
                    prop_assert!(s.is_ascii());
                    prop_assert!(s.starts_with("<svg ") && s.ends_with("</svg>"));
                    prop_assert!(s.matches("<g ").count() <= MAX_ATOMS+2);
                }
            }
        }
        #[test]
        fn siblings_share_only_family(scope in any_array(),owner in any_array(),a in any_array(),b in any_array()) {
            let pa=Portrait::from_public_hints(scope,owner,a);
            let pb=Portrait::from_public_hints(scope,owner,b);
            prop_assert_eq!(pa.family_traits(),pb.family_traits());
            if a!=b { prop_assert_ne!(pa.cache_key(),pb.cache_key()); }
        }
    }
    fn any_array() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>()
    }
    #[test]
    fn domains_roles_and_scope_are_distinct() {
        let p = Portrait::from_public_hints([0; 32], [1; 32], [2; 32]);
        assert_ne!(
            p.cache_key(),
            Portrait::from_public_hints([0; 32], [2; 32], [1; 32]).cache_key()
        );
        assert_ne!(
            p.family_traits(),
            Portrait::from_public_hints([3; 32], [1; 32], [2; 32]).family_traits()
        );
        assert!(!p.svg(Theme::Mono, Detail::Compact).contains("<pattern"));
    }
    #[test]
    fn every_topology_stays_in_the_canvas() {
        // Host-only exact trigonometry checks the actual SVG rotation, plus stroke margin.
        for topology in 0..16 {
            for count in 3..=7 {
                for reach in 25..=37 {
                    for width in 10..=17 {
                        for turn in (0..360).step_by(15) {
                            let atoms = layout(AgentTraits {
                                topology,
                                count,
                                reach,
                                width,
                                turn,
                                core: 0,
                            });
                            assert!(atoms.len() <= MAX_ATOMS);
                            let (cx, cy, span) = layout_bounds(&atoms);
                            let scale = f64::from(116_000 / span) / 1000.0;
                            for a in atoms {
                                for x in [-a.w, a.w] {
                                    for y in [-a.h, a.h] {
                                        let rad = f64::from(a.turn).to_radians();
                                        let px = f64::from(a.x) + f64::from(x) * rad.cos()
                                            - f64::from(y) * rad.sin();
                                        let py = f64::from(a.y)
                                            + f64::from(x) * rad.sin()
                                            + f64::from(y) * rad.cos();
                                        let px = 64.0 + (px - f64::from(cx)) * scale;
                                        let py = 64.0 + (py - f64::from(cy)) * scale;
                                        assert!(
                                            (4.0..=124.0).contains(&px)
                                                && (4.0..=124.0).contains(&py),
                                            "{topology}: {px},{py}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
