//! Fuzz tests for A3Schema validation using proptest.

use a3::prelude::*;
use a3::schema::A3Validate;
use proptest::prelude::*;

#[derive(A3Schema, Debug, Deserialize)]
struct FuzzInput {
    #[a3(min_length = 3, max_length = 30, pattern = "^[a-zA-Z0-9_]+$")]
    #[a3(sanitize(trim))]
    pub username: String,

    #[a3(format = "email")]
    #[a3(sanitize(trim, lowercase))]
    pub email: String,

    #[a3(min = 0, max = 150)]
    pub age: i32,

    #[a3(min = 0.0, max = 100.0)]
    pub score: f64,

    #[a3(min_length = 1, max_length = 50)]
    pub nickname: Option<String>,
}

proptest! {
    #[test]
    fn validate_never_panics(
        username in ".*",
        email in ".*",
        age in i32::MIN..i32::MAX,
        score in f64::MIN..f64::MAX,
        nickname in proptest::option::of(".*"),
    ) {
        let mut input = FuzzInput {
            username,
            email,
            age,
            score,
            nickname,
        };
        // Should never panic — it should return Ok or Err
        let _ = input.validate();
    }

    #[test]
    fn valid_inputs_pass(
        username in "[a-zA-Z0-9_]{3,30}",
        email_local in "[a-zA-Z0-9]{1,10}",
        email_domain in "[a-zA-Z]{2,10}",
        age in 0..=150i32,
        score in 0.0..=100.0f64,
    ) {
        let email = format!("{}@{}.com", email_local, email_domain);
        let mut input = FuzzInput {
            username,
            email,
            age,
            score,
            nickname: None,
        };
        prop_assert!(input.validate().is_ok());
    }

    #[test]
    fn too_short_username_always_fails(
        username in "[a-zA-Z0-9_]{0,2}",
    ) {
        let mut input = FuzzInput {
            username,
            email: "test@example.com".to_string(),
            age: 25,
            score: 50.0,
            nickname: None,
        };
        prop_assert!(input.validate().is_err());
    }

    #[test]
    fn sanitization_is_idempotent(
        raw in "\\s*[a-zA-Z0-9_]{3,20}\\s*",
    ) {
        let mut input1 = FuzzInput {
            username: raw.clone(),
            email: "test@example.com".to_string(),
            age: 25,
            score: 50.0,
            nickname: None,
        };
        let _ = input1.validate();
        let sanitized = input1.username.clone();

        let mut input2 = FuzzInput {
            username: sanitized.clone(),
            email: "test@example.com".to_string(),
            age: 25,
            score: 50.0,
            nickname: None,
        };
        let _ = input2.validate();

        prop_assert_eq!(sanitized, input2.username);
    }
}
