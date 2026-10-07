//! Synthetic PII-shaped payload fields. The measurement rule set in `docs/performance.md`
//! (drop `password` and `headers.authorization`, hash `user.email`, mask SSN-shaped and
//! `secret=...` strings) only costs anything if records actually contain those paths.

use serde_json::{Value, json};

/// Fields that match the benchmark redaction rules; `n` makes every record distinct.
pub fn pii_fields(n: u64) -> Value {
    json!({
        "password": format!("pw-{n}-hunter2"),
        "headers": { "authorization": format!("Bearer tok{n}") },
        "user": { "email": format!("user{n}@example.com") },
        "note": format!("ssn 123-45-6789 for case {n} secret=tok{n} end"),
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pii_fields_carry_every_key_the_documented_rule_set_targets() {
        let v = pii_fields(7);
        assert!(v["password"].is_string());
        assert!(v["headers"]["authorization"].is_string());
        assert!(v["user"]["email"].as_str().unwrap().contains('@'));
        let msg = v["note"].as_str().unwrap();
        assert!(msg.contains("123-45-6789") && msg.contains("secret=tok7"));
    }

    #[test]
    fn pii_fields_are_distinct_per_sequence_number() {
        assert_ne!(
            pii_fields(1)["user"]["email"],
            pii_fields(2)["user"]["email"]
        );
    }
}
