//! Implementation of `#[derive(A3Error)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Lit};

/// Parsed attributes from `#[a3(...)]` on a single enum variant.
#[derive(Default, Debug)]
struct VariantAttrs {
    status: Option<u16>,
    message: Option<String>,
    retryable: bool,
}

pub fn expand(input: &DeriveInput) -> TokenStream {
    let enum_name = &input.ident;

    let variants = match &input.data {
        Data::Enum(data) => &data.variants,
        _ => {
            return syn::Error::new_spanned(enum_name, "A3Error can only be derived on enums")
                .to_compile_error();
        }
    };

    let mut status_arms = Vec::new();
    let mut message_arms = Vec::new();
    let mut code_arms = Vec::new();
    let mut retryable_arms = Vec::new();
    let mut openapi_variants = Vec::new();

    for variant in variants {
        let variant_name = &variant.ident;
        let attrs = parse_variant_attrs(variant);

        // Require status
        let status = match attrs.status {
            Some(s) => s,
            None => {
                return syn::Error::new_spanned(
                    variant_name,
                    format!(
                        "A3Error variant `{}` requires #[a3(status = NNN)]",
                        variant_name
                    ),
                )
                .to_compile_error();
            }
        };

        // Require message
        let message = match &attrs.message {
            Some(m) => m.clone(),
            None => {
                return syn::Error::new_spanned(
                    variant_name,
                    format!(
                        "A3Error variant `{}` requires #[a3(message = \"...\")]",
                        variant_name
                    ),
                )
                .to_compile_error();
            }
        };

        // Generate snake_case code from variant name (e.g., NotFound → "not_found")
        let code_str = to_snake_case(&variant_name.to_string());
        let retryable = attrs.retryable;

        // Match pattern depends on whether the variant has fields
        let pattern = match &variant.fields {
            Fields::Unit => quote! { Self::#variant_name },
            Fields::Unnamed(_) => quote! { Self::#variant_name(..) },
            Fields::Named(_) => quote! { Self::#variant_name { .. } },
        };

        status_arms.push(quote! {
            #pattern => ::a3::axum::http::StatusCode::from_u16(#status).unwrap_or(::a3::axum::http::StatusCode::INTERNAL_SERVER_ERROR)
        });
        message_arms.push(quote! {
            #pattern => #message
        });
        code_arms.push(quote! {
            #pattern => #code_str
        });
        retryable_arms.push(quote! {
            #pattern => #retryable
        });

        openapi_variants.push(quote! {
            a3::error::OpenApiErrorVariant {
                status: #status,
                code: #code_str.to_string(),
                message: #message.to_string(),
                retryable: #retryable,
            }
        });
    }

    quote! {
        impl a3::error::A3ErrorInfo for #enum_name {
            fn status_code(&self) -> ::a3::axum::http::StatusCode {
                match self {
                    #(#status_arms),*
                }
            }

            fn message(&self) -> &str {
                match self {
                    #(#message_arms),*
                }
            }

            fn code(&self) -> &str {
                match self {
                    #(#code_arms),*
                }
            }

            fn retryable(&self) -> bool {
                match self {
                    #(#retryable_arms),*
                }
            }

            fn openapi_responses() -> Vec<a3::error::OpenApiErrorVariant> {
                vec![#(#openapi_variants),*]
            }
        }

        impl ::a3::axum::response::IntoResponse for #enum_name {
            fn into_response(self) -> ::a3::axum::response::Response {
                let request_id = ::a3::uuid::Uuid::new_v4().to_string();
                a3::error::into_a3_response(&self, &request_id)
            }
        }
    }
}

/// Parse all `#[a3(...)]` attributes on an enum variant.
fn parse_variant_attrs(variant: &syn::Variant) -> VariantAttrs {
    let mut attrs = VariantAttrs::default();

    for attr in &variant.attrs {
        if !attr.path().is_ident("a3") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            let ident = meta.path.get_ident().map(|i| i.to_string());
            match ident.as_deref() {
                Some("status") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Int(n) = lit {
                        attrs.status = Some(n.base10_parse()?);
                    }
                }
                Some("message") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        attrs.message = Some(s.value());
                    }
                }
                Some("retryable") => {
                    attrs.retryable = true;
                }
                _ => {}
            }
            Ok(())
        });
    }

    attrs
}

/// Convert PascalCase to snake_case (e.g., "NotFound" → "not_found").
fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                result.push('_');
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}
