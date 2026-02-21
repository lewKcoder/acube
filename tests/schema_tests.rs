//! Tests for `#[derive(A3Schema)]` — Phase 1a.

use a3::prelude::*;
use a3::schema::{check_unknown_fields, A3SchemaInfo, A3Validate};

// ─── Test structs ───────────────────────────────────────────────────────────

#[derive(A3Schema, Debug, Deserialize)]
struct UsernameInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,
}

#[derive(A3Schema, Debug, Deserialize)]
struct EmailInput {
    #[a3(format = "email", pii)]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,
}

#[derive(A3Schema, Debug, Deserialize)]
struct DisplayNameInput {
    #[a3(min_length = 1, max_length = 100)]
    #[a3(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(A3Schema, Debug, Deserialize)]
struct AgeInput {
    #[a3(min = 0, max = 150)]
    pub age: i32,
}

#[derive(A3Schema, Debug, Deserialize)]
struct ScoreInput {
    #[a3(min = 0.0, max = 100.0)]
    pub score: f64,
}

#[derive(A3Schema, Debug, Deserialize)]
struct OptionalInput {
    #[a3(min_length = 1, max_length = 50)]
    pub nickname: Option<String>,
}

#[derive(A3Schema, Debug, Deserialize)]
struct TagsInput {
    #[a3(min_length = 1, max_length = 20)]
    #[a3(sanitize(trim))]
    pub tags: Vec<String>,
}

#[derive(A3Schema, Debug, Deserialize)]
struct UuidInput {
    #[a3(format = "uuid")]
    pub id: String,
}

#[derive(A3Schema, Debug, Deserialize)]
struct MultiFieldInput {
    #[a3(min_length = 3, max_length = 30)]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email")]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min = 18, max = 120)]
    pub age: i32,
}

#[derive(A3Schema, Debug, Deserialize)]
struct NoAttrsInput {
    pub name: String,
    pub active: bool,
}

#[derive(A3Schema, Debug, Deserialize)]
struct I64Input {
    #[a3(min = 0, max = 1000000)]
    pub big_number: i64,
}

// ─── Validation tests ───────────────────────────────────────────────────────

#[test]
fn username_valid() {
    let mut input = UsernameInput {
        username: "alice_42".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn username_too_short() {
    let mut input = UsernameInput {
        username: "ab".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].code, "min_length");
    assert_eq!(err[0].field, "username");
}

#[test]
fn username_too_long() {
    let mut input = UsernameInput {
        username: "a".repeat(31),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max_length");
}

#[test]
fn username_bad_pattern() {
    let mut input = UsernameInput {
        username: "alice!@#".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert!(err.iter().any(|e| e.code == "pattern"));
}

#[test]
fn username_trimmed() {
    let mut input = UsernameInput {
        username: "  alice  ".to_string(),
    };
    let _ = input.validate();
    assert_eq!(input.username, "alice");
}

#[test]
fn email_valid() {
    let mut input = EmailInput {
        email: "alice@example.com".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn email_invalid() {
    let mut input = EmailInput {
        email: "not-an-email".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn email_sanitized_trim_and_lowercase() {
    let mut input = EmailInput {
        email: "  Alice@Example.COM  ".to_string(),
    };
    let _ = input.validate();
    assert_eq!(input.email, "alice@example.com");
}

#[test]
fn display_name_strip_html() {
    let mut input = DisplayNameInput {
        display_name: "<script>alert('xss')</script>Alice".to_string(),
    };
    let _ = input.validate();
    assert_eq!(input.display_name, "alert('xss')Alice");
}

#[test]
fn display_name_empty_after_trim() {
    let mut input = DisplayNameInput {
        display_name: "   ".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "min_length");
}

#[test]
fn age_valid() {
    let mut input = AgeInput { age: 25 };
    assert!(input.validate().is_ok());
}

#[test]
fn age_below_min() {
    let mut input = AgeInput { age: -1 };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "min");
}

#[test]
fn age_above_max() {
    let mut input = AgeInput { age: 200 };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max");
}

#[test]
fn score_valid() {
    let mut input = ScoreInput { score: 55.5 };
    assert!(input.validate().is_ok());
}

#[test]
fn score_below_min() {
    let mut input = ScoreInput { score: -0.1 };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "min");
}

#[test]
fn score_above_max() {
    let mut input = ScoreInput { score: 100.1 };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max");
}

#[test]
fn optional_none_is_valid() {
    let mut input = OptionalInput { nickname: None };
    assert!(input.validate().is_ok());
}

#[test]
fn optional_some_valid() {
    let mut input = OptionalInput {
        nickname: Some("nick".to_string()),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn optional_some_too_long() {
    let mut input = OptionalInput {
        nickname: Some("a".repeat(51)),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max_length");
}

#[test]
fn tags_valid() {
    let mut input = TagsInput {
        tags: vec!["rust".to_string(), "web".to_string()],
    };
    assert!(input.validate().is_ok());
}

#[test]
fn tags_empty_element() {
    let mut input = TagsInput {
        tags: vec!["".to_string()],
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "min_length");
    assert!(err[0].field.contains("[0]"));
}

#[test]
fn tags_element_too_long() {
    let mut input = TagsInput {
        tags: vec!["a".repeat(21)],
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max_length");
}

#[test]
fn tags_sanitized() {
    let mut input = TagsInput {
        tags: vec!["  rust  ".to_string()],
    };
    let _ = input.validate();
    assert_eq!(input.tags[0], "rust");
}

#[test]
fn uuid_valid() {
    let mut input = UuidInput {
        id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn uuid_invalid() {
    let mut input = UuidInput {
        id: "not-a-uuid".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn multi_field_all_valid() {
    let mut input = MultiFieldInput {
        username: "alice".to_string(),
        email: "alice@example.com".to_string(),
        age: 25,
    };
    assert!(input.validate().is_ok());
}

#[test]
fn multi_field_multiple_errors() {
    let mut input = MultiFieldInput {
        username: "ab".to_string(),
        email: "bad".to_string(),
        age: 10,
    };
    let err = input.validate().unwrap_err();
    // Should have errors for username (min_length), email (format), and age (min)
    assert!(err.len() >= 3);
}

#[test]
fn no_attrs_always_valid() {
    let mut input = NoAttrsInput {
        name: "anything".to_string(),
        active: true,
    };
    assert!(input.validate().is_ok());
}

#[test]
fn i64_valid() {
    let mut input = I64Input { big_number: 500000 };
    assert!(input.validate().is_ok());
}

#[test]
fn i64_above_max() {
    let mut input = I64Input {
        big_number: 1000001,
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "max");
}

// ─── Strict mode (unknown field rejection) ──────────────────────────────────

#[test]
fn strict_mode_rejects_unknown_fields() {
    let json = serde_json::json!({
        "username": "alice",
        "evil_field": "injected"
    });
    let errors = check_unknown_fields(&json, UsernameInput::known_fields());
    assert_eq!(errors.len(), 1);
    assert_eq!(errors[0].code, "unknown_field");
    assert_eq!(errors[0].field, "evil_field");
}

#[test]
fn strict_mode_allows_known_fields() {
    let json = serde_json::json!({
        "username": "alice"
    });
    let errors = check_unknown_fields(&json, UsernameInput::known_fields());
    assert!(errors.is_empty());
}

// ─── Schema info tests ─────────────────────────────────────────────────────

#[test]
fn schema_info_name() {
    let info = MultiFieldInput::schema_info();
    assert_eq!(info.name, "MultiFieldInput");
}

#[test]
fn schema_info_field_count() {
    let info = MultiFieldInput::schema_info();
    assert_eq!(info.fields.len(), 3);
}

#[test]
fn schema_info_pii_flag() {
    let info = EmailInput::schema_info();
    assert!(info.fields[0].pii);
}

#[test]
fn schema_info_optional_not_required() {
    let info = OptionalInput::schema_info();
    assert!(!info.fields[0].required);
}

#[test]
fn schema_info_required_field() {
    let info = UsernameInput::schema_info();
    assert!(info.fields[0].required);
}
