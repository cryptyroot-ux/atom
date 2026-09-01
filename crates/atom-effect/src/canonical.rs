//! RFC 8785 (JSON Canonicalization Scheme) + the canonical request digest.
//!
//! ATOM refuses to hash an ambiguous request. Two byte strings that mean the
//! same JSON — keys in a different order, extra whitespace, a different but
//! equal escaping — must have the SAME identity, and any value change a
//! DIFFERENT one (EFX-005, ATOM-SEM-003). RFC 8785 gives exactly one byte
//! string per JSON value:
//!
//!   * object members sorted by the UTF-16 code units of their names,
//!   * no insignificant whitespace,
//!   * RFC 8785 §3.2.2.2 string escaping (minimal, lower-case `\uXXXX`),
//!   * literals `true` / `false` / `null` verbatim.
//!
//! Numbers are the one place a hand-rolled canonicalizer can silently diverge
//! from other languages (the ECMAScript number rule is subtle). ATOM refuses a
//! non-integer number outright rather than emit a digest that would not
//! reproduce cross-language — a deliberate *strengthening* of the RFC that is
//! safe for structured effect requests: represent a decimal as a string and it
//! canonicalizes unambiguously. Integers in the `i64`/`u64` range serialize to
//! their exact decimal form, which the RFC's number rule also produces.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// A request body could not be canonicalized under RFC 8785.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CanonicalizationError {
    /// A non-integer JSON number was encountered. RFC 8785's ECMAScript number
    /// serialization is not reproduced here on purpose; carry decimals as
    /// strings so the digest is interoperable.
    #[error(
        "RFC 8785 canonicalization refuses non-integer number `{0}`; carry decimals as strings"
    )]
    NonIntegerNumber(String),
}

/// The canonical UTF-8 bytes of `value` under RFC 8785 (JCS).
///
/// # Errors
///
/// [`CanonicalizationError::NonIntegerNumber`] if `value` contains a
/// floating-point number anywhere in its tree.
pub fn to_canonical_bytes(value: &Value) -> Result<Vec<u8>, CanonicalizationError> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out.into_bytes())
}

/// The canonical request digest: `sha256:` over the RFC 8785 bytes of `value`.
///
/// This is the only sanctioned way to mint an `EffectIntent`'s
/// `canonical_request_digest`, so a reordered or reformatted request keeps one
/// identity and a mutated request earns a new one.
///
/// # Errors
///
/// [`CanonicalizationError::NonIntegerNumber`] if `value` contains a
/// floating-point number anywhere in its tree.
pub fn canonical_request_digest(value: &Value) -> Result<String, CanonicalizationError> {
    let bytes = to_canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn write_value(value: &Value, out: &mut String) -> Result<(), CanonicalizationError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(members) => write_object(members, out)?,
    }
    Ok(())
}

/// Members are emitted in ascending order of their names' UTF-16 code units,
/// as RFC 8785 §3.2.3 requires — not the UTF-8 byte order a `BTreeMap` would
/// give, which differs for code points above the basic multilingual plane.
fn write_object(
    members: &Map<String, Value>,
    out: &mut String,
) -> Result<(), CanonicalizationError> {
    let mut names: Vec<&String> = members.keys().collect();
    names.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
    out.push('{');
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_string(name, out);
        out.push(':');
        write_value(&members[*name], out)?;
    }
    out.push('}');
    Ok(())
}

fn write_number(
    number: &serde_json::Number,
    out: &mut String,
) -> Result<(), CanonicalizationError> {
    if let Some(unsigned) = number.as_u64() {
        out.push_str(&unsigned.to_string());
    } else if let Some(signed) = number.as_i64() {
        out.push_str(&signed.to_string());
    } else {
        return Err(CanonicalizationError::NonIntegerNumber(number.to_string()));
    }
    Ok(())
}

/// RFC 8785 §3.2.2.2 string serialization: escape `"` and `\`, use the short
/// escapes for the five named control characters, `\uXXXX` (lower-case hex) for
/// every other C0 control, and emit all other characters — including non-ASCII
/// — as their literal UTF-8.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{09}' => out.push_str("\\t"),
            '\u{0A}' => out.push_str("\\n"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{0D}' => out.push_str("\\r"),
            control if (control as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Reordering members must not change the identity: RFC 8785 sorts them.
    #[test]
    fn key_order_does_not_change_the_digest() {
        let one = json!({ "b": 1, "a": 2, "c": 3 });
        let two = json!({ "c": 3, "a": 2, "b": 1 });
        assert_eq!(
            canonical_request_digest(&one).unwrap(),
            canonical_request_digest(&two).unwrap()
        );
    }

    /// Insignificant whitespace must not change the identity.
    #[test]
    fn whitespace_does_not_change_the_digest() {
        let dense: Value = serde_json::from_str(r#"{"a":1,"b":[2,3]}"#).unwrap();
        let spaced: Value = serde_json::from_str("{ \"a\" : 1 ,\n  \"b\" : [ 2 , 3 ]\t}").unwrap();
        assert_eq!(
            canonical_request_digest(&dense).unwrap(),
            canonical_request_digest(&spaced).unwrap()
        );
    }

    /// Any value change must earn a new identity.
    #[test]
    fn a_changed_value_changes_the_digest() {
        let before = json!({ "amount": 100, "to": "acct-1" });
        let after = json!({ "amount": 101, "to": "acct-1" });
        assert_ne!(
            canonical_request_digest(&before).unwrap(),
            canonical_request_digest(&after).unwrap()
        );
    }

    /// RFC 8785 §3.2.3 sorts by UTF-16 code units, not Unicode code points: a
    /// key whose first UTF-16 unit is a high surrogate (`U+10000` → `0xD800`)
    /// sorts *before* one in the private-use area (`U+E000`), the reverse of
    /// code-point order. This is exactly where a naive `BTreeMap` (UTF-8) order
    /// diverges.
    #[test]
    fn object_members_sort_by_utf16_code_units() {
        let astral = "\u{10000}";
        let bmp = "\u{E000}";
        let mut map = Map::new();
        map.insert(bmp.to_owned(), json!(1));
        map.insert(astral.to_owned(), json!(2));
        let bytes = to_canonical_bytes(&Value::Object(map)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(
            text.find(astral).unwrap() < text.find(bmp).unwrap(),
            "RFC 8785 sorts by UTF-16 code units: {text}"
        );
    }

    /// Integers in range serialize to their exact decimal form.
    #[test]
    fn integers_serialize_verbatim() {
        assert_eq!(to_canonical_bytes(&json!(0)).unwrap(), b"0");
        assert_eq!(
            to_canonical_bytes(&json!(9_007_199_254_740_993_u64)).unwrap(),
            b"9007199254740993"
        );
        assert_eq!(to_canonical_bytes(&json!(-42)).unwrap(), b"-42");
    }

    /// A non-integer number is refused, not silently mis-serialized.
    #[test]
    fn a_non_integer_number_is_refused() {
        let error = canonical_request_digest(&json!({ "rate": 0.1 })).unwrap_err();
        assert!(matches!(error, CanonicalizationError::NonIntegerNumber(_)));
    }

    /// RFC 8785 §3.2.2.2 escaping: named short escapes and lower-case `\uXXXX`
    /// for other C0 controls; non-ASCII stays literal UTF-8.
    #[test]
    fn control_characters_use_rfc8785_escapes() {
        let bytes = to_canonical_bytes(&json!("a\n\t\u{01}€")).unwrap();
        assert_eq!(String::from_utf8(bytes).unwrap(), "\"a\\n\\t\\u0001€\"");
    }

    /// The digest always has the canonical `sha256:<64 lower-hex>` shape.
    #[test]
    fn the_digest_has_the_canonical_shape() {
        let digest = canonical_request_digest(&json!({ "x": 1 })).unwrap();
        let hex = digest.strip_prefix("sha256:").expect("sha256: prefix");
        assert_eq!(hex.len(), 64);
        assert!(hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    }
}
