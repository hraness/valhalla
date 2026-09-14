//! Structured terminal presentation: every string is escaped to ASCII JSON.
//! Generic helpers shared by the social and rooms command surfaces.
use vhalla_social::RecordId;

pub fn string(value: &str) -> String {
    let mut out = String::from("\"");
    for unit in value.encode_utf16() {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x20..=0x7e => out.push(char::from_u32(u32::from(unit)).expect("ASCII")),
            _ => out.push_str(&format!("\\u{unit:04x}")),
        }
    }
    out.push('"');
    out
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn id(bytes: &[u8]) -> String {
    string(&hex(bytes))
}
pub fn object(fields: Vec<(&str, String)>) -> String {
    format!(
        "{{{}}}",
        fields
            .into_iter()
            .map(|(key, value)| format!("{}:{value}", string(key)))
            .collect::<Vec<_>>()
            .join(",")
    )
}
pub fn array(values: impl IntoIterator<Item = String>) -> String {
    format!("[{}]", values.into_iter().collect::<Vec<_>>().join(","))
}
pub fn ids(values: &[RecordId]) -> String {
    array(values.iter().map(|v| id(v.as_bytes())))
}
pub fn optional<T>(value: Option<T>, f: impl FnOnce(T) -> String) -> String {
    value.map(f).unwrap_or_else(|| "null".into())
}

#[cfg(test)]
mod tests {
    #[test]
    fn escaping_roundtrips_controls_and_supplementary_unicode_through_independent_parser() {
        let ascii = (0..=127u8).map(char::from).collect::<String>();
        for original in [
            ascii.as_str(),
            "\u{2028}\u{202e}\u{2066} 🦀 𐐀 \u{10ffff}",
            "<script>\"quoted\"\\end",
        ] {
            let encoded = super::string(original);
            assert!(encoded.bytes().all(|v| (0x20..=0x7e).contains(&v)));
            assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), original);
        }
    }
}
