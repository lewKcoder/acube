//! Tests for `#[derive(AcubeSchema)]` — Phase 1a.

use acube::prelude::*;
use acube::schema::{check_unknown_fields, AcubeSchemaInfo, AcubeValidate};

// ─── Test structs ───────────────────────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
struct UsernameInput {
    #[acube(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[acube(sanitize(trim))]
    pub username: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct EmailInput {
    #[acube(format = "email", pii)]
    #[acube(sanitize(trim, lowercase))]
    pub email: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct DisplayNameInput {
    #[acube(min_length = 1, max_length = 100)]
    #[acube(sanitize(trim, strip_html))]
    pub display_name: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct AgeInput {
    #[acube(min = 0, max = 150)]
    pub age: i32,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct ScoreInput {
    #[acube(min = 0.0, max = 100.0)]
    pub score: f64,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct OptionalInput {
    #[acube(min_length = 1, max_length = 50)]
    pub nickname: Option<String>,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct TagsInput {
    #[acube(min_length = 1, max_length = 20)]
    #[acube(sanitize(trim))]
    pub tags: Vec<String>,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct UrlInput {
    #[acube(format = "url")]
    pub link: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct UuidInput {
    #[acube(format = "uuid")]
    pub id: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct MultiFieldInput {
    #[acube(min_length = 3, max_length = 30)]
    #[acube(sanitize(trim))]
    pub username: String,

    #[acube(format = "email")]
    #[acube(sanitize(trim, lowercase))]
    pub email: String,

    #[acube(min = 18, max = 120)]
    pub age: i32,
}

#[derive(AcubeSchema, Debug, Deserialize)]
#[allow(dead_code)]
struct NoAttrsInput {
    pub name: String,
    pub active: bool,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct I64Input {
    #[acube(min = 0, max = 1000000)]
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

// ─── URL format validation ──────────────────────────────────────────────────

#[test]
fn url_https_valid() {
    let mut input = UrlInput {
        link: "https://example.com".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_http_valid() {
    let mut input = UrlInput {
        link: "http://example.com".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_with_path_valid() {
    let mut input = UrlInput {
        link: "https://example.com/path/to/page".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_with_query_valid() {
    let mut input = UrlInput {
        link: "https://example.com/search?q=rust&page=1".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_with_port_valid() {
    let mut input = UrlInput {
        link: "http://localhost:3000/api".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_subdomain_valid() {
    let mut input = UrlInput {
        link: "https://docs.rs/acube/latest".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn url_no_scheme_invalid() {
    let mut input = UrlInput {
        link: "example.com".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn url_ftp_invalid() {
    let mut input = UrlInput {
        link: "ftp://example.com".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn url_empty_invalid() {
    let mut input = UrlInput {
        link: "".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn url_just_scheme_invalid() {
    let mut input = UrlInput {
        link: "https://".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

#[test]
fn url_random_string_invalid() {
    let mut input = UrlInput {
        link: "not a url at all".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "format");
}

// ─── Nested AcubeSchema validation tests ────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
struct InnerInput {
    #[acube(min_length = 1, max_length = 50)]
    #[acube(sanitize(trim))]
    pub name: String,

    #[acube(min = 0, max = 100)]
    pub value: i32,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct OuterInput {
    #[acube(min_length = 1)]
    pub title: String,
    pub inner: InnerInput,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct OuterOptionInput {
    pub inner: Option<InnerInput>,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct OuterVecInput {
    pub items: Vec<InnerInput>,
}

#[test]
fn nested_struct_valid() {
    let mut input = OuterInput {
        title: "hello".to_string(),
        inner: InnerInput {
            name: "item".to_string(),
            value: 50,
        },
    };
    assert!(input.validate().is_ok());
}

#[test]
fn nested_struct_inner_invalid() {
    let mut input = OuterInput {
        title: "hello".to_string(),
        inner: InnerInput {
            name: "".to_string(), // too short
            value: 50,
        },
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].field, "inner.name");
    assert_eq!(err[0].code, "min_length");
}

#[test]
fn nested_struct_both_invalid() {
    let mut input = OuterInput {
        title: "".to_string(), // outer invalid
        inner: InnerInput {
            name: "ok".to_string(),
            value: 200, // inner invalid
        },
    };
    let err = input.validate().unwrap_err();
    assert!(err.len() >= 2);
    assert!(err.iter().any(|e| e.field == "title"));
    assert!(err.iter().any(|e| e.field == "inner.value"));
}

#[test]
fn nested_struct_sanitization() {
    let mut input = OuterInput {
        title: "test".to_string(),
        inner: InnerInput {
            name: "  padded  ".to_string(),
            value: 10,
        },
    };
    let _ = input.validate();
    assert_eq!(input.inner.name, "padded");
}

#[test]
fn nested_option_none_valid() {
    let mut input = OuterOptionInput { inner: None };
    assert!(input.validate().is_ok());
}

#[test]
fn nested_option_some_valid() {
    let mut input = OuterOptionInput {
        inner: Some(InnerInput {
            name: "ok".to_string(),
            value: 50,
        }),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn nested_option_some_invalid() {
    let mut input = OuterOptionInput {
        inner: Some(InnerInput {
            name: "".to_string(),
            value: 50,
        }),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].field, "inner.name");
}

#[test]
fn nested_vec_valid() {
    let mut input = OuterVecInput {
        items: vec![
            InnerInput {
                name: "a".to_string(),
                value: 1,
            },
            InnerInput {
                name: "b".to_string(),
                value: 2,
            },
        ],
    };
    assert!(input.validate().is_ok());
}

#[test]
fn nested_vec_element_invalid() {
    let mut input = OuterVecInput {
        items: vec![
            InnerInput {
                name: "ok".to_string(),
                value: 1,
            },
            InnerInput {
                name: "".to_string(), // invalid
                value: 200,           // also invalid
            },
        ],
    };
    let err = input.validate().unwrap_err();
    assert!(err.iter().any(|e| e.field == "items[1].name"));
    assert!(err.iter().any(|e| e.field == "items[1].value"));
}

#[test]
fn nested_vec_empty_valid() {
    let mut input = OuterVecInput { items: vec![] };
    assert!(input.validate().is_ok());
}

#[test]
fn nested_vec_multiple_elements_invalid() {
    let mut input = OuterVecInput {
        items: vec![
            InnerInput {
                name: "".to_string(),
                value: 1,
            },
            InnerInput {
                name: "".to_string(),
                value: 2,
            },
        ],
    };
    let err = input.validate().unwrap_err();
    assert!(err.iter().any(|e| e.field == "items[0].name"));
    assert!(err.iter().any(|e| e.field == "items[1].name"));
}

// ─── one_of validation tests ─────────────────────────────────────────────────

#[derive(AcubeSchema, Debug, Deserialize)]
struct StatusInput {
    #[acube(one_of = ["draft", "published", "archived"])]
    pub status: String,
}

#[derive(AcubeSchema, Debug, Deserialize)]
struct OptionalStatusInput {
    #[acube(one_of = ["active", "inactive"])]
    pub status: Option<String>,
}

#[test]
fn one_of_valid_value() {
    let mut input = StatusInput {
        status: "draft".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn one_of_another_valid_value() {
    let mut input = StatusInput {
        status: "published".to_string(),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn one_of_invalid_value() {
    let mut input = StatusInput {
        status: "unknown".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err.len(), 1);
    assert_eq!(err[0].code, "one_of");
    assert_eq!(err[0].field, "status");
    assert!(err[0].message.contains("draft"));
}

#[test]
fn one_of_empty_string_invalid() {
    let mut input = StatusInput {
        status: "".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "one_of");
}

#[test]
fn one_of_case_sensitive() {
    let mut input = StatusInput {
        status: "Draft".to_string(),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "one_of");
}

#[test]
fn one_of_option_none_valid() {
    let mut input = OptionalStatusInput { status: None };
    assert!(input.validate().is_ok());
}

#[test]
fn one_of_option_some_valid() {
    let mut input = OptionalStatusInput {
        status: Some("active".to_string()),
    };
    assert!(input.validate().is_ok());
}

#[test]
fn one_of_option_some_invalid() {
    let mut input = OptionalStatusInput {
        status: Some("deleted".to_string()),
    };
    let err = input.validate().unwrap_err();
    assert_eq!(err[0].code, "one_of");
}
