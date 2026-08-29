//! RFC 8785 JSON Canonicalization Scheme (JCS), the canonical encoding mandated by
//! ADR-020.
//!
//! Two independent implementations must derive byte-identical encodings for the same
//! JSON value, otherwise they derive different event identities. The rules applied here:
//!
//! * object members are sorted by their key's UTF-16 code unit sequence,
//! * no insignificant whitespace,
//! * strings carry the minimal JSON escape set, with control characters as `\u00xx`,
//! * numbers use the ECMAScript `Number::toString` form.
//!
//! Two deliberate boundaries:
//!
//! * Integers beyond ±2^53 are **rejected** ([`crate::Error::UnrepresentableNumber`])
//!   rather than rounded to the nearest double. Rounding would produce two different
//!   canonical forms for one input across implementations; refusing cannot.
//! * Lone surrogates are unreachable — a Rust `str` is always well-formed UTF-8 — so the
//!   RFC's lone-surrogate rule has no code path here.

use std::cmp::Ordering;

use serde_json::{Number, Value};

use crate::error::{Error, Result};

/// Largest integer an IEEE 754 double represents exactly (`Number.MAX_SAFE_INTEGER + 1`).
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_992;

/// Canonicalize `value` into RFC 8785 UTF-8 bytes.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Order two object keys the way RFC 8785 requires: by UTF-16 code units, which differs
/// from Rust's byte ordering for code points above the BMP.
fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|left, right| utf16_cmp(left, right));
            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(&members[key], out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn write_number(number: &Number, out: &mut Vec<u8>) -> Result<()> {
    if let Some(unsigned) = number.as_u64() {
        return write_integer(unsigned, false, out);
    }
    if let Some(signed) = number.as_i64() {
        return write_integer(signed.unsigned_abs(), signed < 0, out);
    }
    let float = number
        .as_f64()
        .filter(|float| float.is_finite())
        .ok_or_else(|| Error::UnrepresentableNumber {
            value: number.to_string(),
        })?;
    out.extend_from_slice(format_double(float).as_bytes());
    Ok(())
}

fn write_integer(magnitude: u64, negative: bool, out: &mut Vec<u8>) -> Result<()> {
    if magnitude > MAX_SAFE_INTEGER {
        return Err(Error::UnrepresentableNumber {
            value: format!("{}{magnitude}", if negative { "-" } else { "" }),
        });
    }
    if negative && magnitude != 0 {
        out.push(b'-');
    }
    out.extend_from_slice(magnitude.to_string().as_bytes());
    Ok(())
}

/// ECMAScript `Number::toString` for a finite double, which is what RFC 8785 prescribes
/// for JSON numbers.
///
/// Rust's `{:e}` already yields the shortest round-tripping digit string — the same digits
/// ECMAScript picks — so the work here is purely re-placing the decimal point and deciding
/// between positional and exponential form.
fn format_double(value: f64) -> String {
    if value == 0.0 {
        // Covers -0.0: RFC 8785 and JSON.stringify both render it as `0`.
        return "0".to_owned();
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific
        .split_once('e')
        .expect("`{:e}` always emits an exponent");
    let exponent: i32 = exponent
        .parse()
        .expect("`{:e}` always emits a decimal exponent");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let digits = digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits };

    // `digits` are d1..dk and the value is 0.d1..dk * 10^n, per ECMAScript 6.1.6.1.20.
    let k = digits.len() as i32;
    let n = exponent + 1;

    let mut out = String::new();
    if value < 0.0 {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(digits);
        out.push_str(&"0".repeat((n - k) as usize));
    } else if 0 < n && n <= 21 {
        out.push_str(&digits[..n as usize]);
        out.push('.');
        out.push_str(&digits[n as usize..]);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        out.push_str(&"0".repeat((-n) as usize));
        out.push_str(digits);
    } else {
        out.push_str(&digits[..1]);
        if k > 1 {
            out.push('.');
            out.push_str(&digits[1..]);
        }
        // The exponent ECMAScript prints is n - 1, and its sign is always explicit.
        let power = n - 1;
        out.push('e');
        out.push(if power < 0 { '-' } else { '+' });
        out.push_str(&power.abs().to_string());
    }
    out
}

/// Write a JSON string literal with the RFC 8785 escape set: only the two mandatory
/// escapes, the five short forms, and `\u00xx` for the remaining C0 controls. Everything
/// else — including DEL and every non-ASCII character — stays literal UTF-8.
fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            control if control < '\u{20}' => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// A field of a normative identity document.
///
/// Identity documents (event identity, checkpoint digest) hold nothing but strings and
/// small integers, so [`identity_document`] can emit them without a fallible path — a
/// normative identity must never depend on an error branch.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Field<'a> {
    Str(&'a str),
    Uint(u64),
    Int(i64),
}

/// Emit a flat RFC 8785 object from pre-sorted fields.
///
/// The caller passes fields in canonical key order; the debug assertion is what keeps that
/// promise honest during development, and `jcs_matches_identity_document` in the tests
/// below pins the output against the general canonicalizer.
pub(crate) fn identity_document(fields: &[(&str, Field<'_>)]) -> Vec<u8> {
    debug_assert!(
        fields
            .windows(2)
            .all(|pair| utf16_cmp(pair[0].0, pair[1].0) == Ordering::Less),
        "identity document keys must be given in RFC 8785 order"
    );
    let mut out = vec![b'{'];
    for (index, (key, field)) in fields.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        write_string(key, &mut out);
        out.push(b':');
        match field {
            Field::Str(text) => write_string(text, &mut out),
            Field::Uint(value) => {
                debug_assert!(*value <= MAX_SAFE_INTEGER, "identity integer out of range");
                out.extend_from_slice(value.to_string().as_bytes());
            }
            Field::Int(value) => {
                debug_assert!(
                    value.unsigned_abs() <= MAX_SAFE_INTEGER,
                    "identity integer out of range"
                );
                out.extend_from_slice(value.to_string().as_bytes());
            }
        }
    }
    out.push(b'}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canonical(value: &Value) -> String {
        String::from_utf8(canonicalize(value).expect("canonicalizable")).expect("utf-8")
    }

    #[test]
    fn numbers_follow_the_ecmascript_form() {
        // RFC 8785 appendix B / ECMAScript Number::toString.
        assert_eq!(format_double(1e30), "1e+30");
        assert_eq!(format_double(1e21), "1e+21");
        assert_eq!(format_double(1e20), "100000000000000000000");
        assert_eq!(format_double(1e-6), "0.000001");
        assert_eq!(format_double(1e-7), "1e-7");
        assert_eq!(format_double(-0.0), "0");
        assert_eq!(format_double(0.5), "0.5");
        assert_eq!(format_double(-0.5), "-0.5");
        assert_eq!(format_double(123.456), "123.456");
        assert_eq!(format_double(100.0), "100");
        assert_eq!(format_double(1.5e-9), "1.5e-9");
        assert_eq!(format_double(f64::MIN_POSITIVE), "2.2250738585072014e-308");
    }

    #[test]
    fn integers_are_exact_and_huge_ones_are_refused() {
        assert_eq!(canonical(&json!(0)), "0");
        assert_eq!(canonical(&json!(-1)), "-1");
        assert_eq!(canonical(&json!(1_756_512_001_000i64)), "1756512001000");
        assert_eq!(canonical(&json!(MAX_SAFE_INTEGER)), "9007199254740992");
        let too_big = json!(MAX_SAFE_INTEGER + 1);
        assert!(matches!(
            canonicalize(&too_big),
            Err(Error::UnrepresentableNumber { .. })
        ));
    }

    #[test]
    fn object_keys_sort_by_utf16_code_units() {
        // RFC 8785 section 3.2.3 worked example.
        let value = json!({"peach": 1, "péché": 2, "pêche": 3, "sin": 4});
        assert_eq!(
            canonical(&value),
            r#"{"peach":1,"péché":2,"pêche":3,"sin":4}"#
        );
        // A supplementary-plane key sorts *before* a BMP key above the surrogate range,
        // which byte ordering would get backwards.
        let value = json!({"\u{e000}": 1, "\u{10000}": 2});
        assert_eq!(canonical(&value), "{\"\u{10000}\":2,\"\u{e000}\":1}");
        assert_eq!(utf16_cmp("\u{10000}", "\u{e000}"), Ordering::Less);
        assert_eq!("\u{10000}".cmp("\u{e000}"), Ordering::Greater);
    }

    #[test]
    fn strings_carry_the_minimal_escape_set() {
        assert_eq!(canonical(&json!("a\"b\\c")), r#""a\"b\\c""#);
        assert_eq!(canonical(&json!("\u{08}\t\n\u{0c}\r")), r#""\b\t\n\f\r""#);
        assert_eq!(canonical(&json!("\u{00}\u{1f}")), r#""\u0000\u001f""#);
        assert_eq!(canonical(&json!("\u{7f}é")), "\"\u{7f}é\"");
    }

    #[test]
    fn structure_is_compact_and_order_preserving_for_arrays() {
        assert_eq!(canonical(&json!([])), "[]");
        assert_eq!(canonical(&json!({})), "{}");
        assert_eq!(canonical(&json!(null)), "null");
        assert_eq!(canonical(&json!([3, 1, 2])), "[3,1,2]");
        assert_eq!(
            canonical(&json!({"b": [true, false], "a": {"y": null, "x": 1}})),
            r#"{"a":{"x":1,"y":null},"b":[true,false]}"#
        );
    }

    /// The infallible identity emitter and the general canonicalizer must agree byte for
    /// byte, or normative identities would drift from ADR-020.
    #[test]
    fn jcs_matches_identity_document() {
        let head_hash = "ab".repeat(32);
        let fields = [
            ("event_count", Field::Uint(7)),
            ("head_hash", Field::Str(&head_hash)),
            ("seq", Field::Uint(7)),
            ("stream_id", Field::Str("mission/01JVT0")),
            ("ts", Field::Int(-1_756_512_000_000)),
        ];
        let value = json!({
            "event_count": 7u64,
            "head_hash": head_hash,
            "seq": 7u64,
            "stream_id": "mission/01JVT0",
            "ts": -1_756_512_000_000i64,
        });
        assert_eq!(
            identity_document(&fields),
            canonicalize(&value).expect("canonicalizable")
        );
    }
}
