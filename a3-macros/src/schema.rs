//! Implementation of `#[derive(A3Schema)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, Lit, Type};

/// Parsed attributes from `#[a3(...)]` on a single field.
#[derive(Default, Debug)]
struct FieldAttrs {
    min_length: Option<usize>,
    max_length: Option<usize>,
    min_i64: Option<i64>,
    max_i64: Option<i64>,
    min_f64: Option<f64>,
    max_f64: Option<f64>,
    pattern: Option<String>,
    format: Option<String>,
    pii: bool,
    sanitize_trim: bool,
    sanitize_lowercase: bool,
    sanitize_strip_html: bool,
}

/// Classify the outermost type of a field for code generation.
#[derive(Debug)]
enum FieldKind {
    String,
    I32,
    I64,
    F64,
    Bool,
    OptionString,
    OptionI32,
    OptionI64,
    OptionF64,
    OptionBool,
    VecString,
    VecI32,
    VecI64,
    VecF64,
    VecBool,
    Other,
}

pub fn expand(input: &DeriveInput) -> TokenStream {
    let struct_name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return syn::Error::new_spanned(struct_name, "A3Schema only supports named fields")
                    .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(struct_name, "A3Schema can only be derived on structs")
                .to_compile_error();
        }
    };

    let mut validate_stmts = Vec::new();
    let mut known_field_names = Vec::new();
    let mut field_infos = Vec::new();

    for field in fields {
        let field_name = field.ident.as_ref().unwrap();
        let field_name_str = field_name.to_string();
        let field_type = &field.ty;
        let kind = classify_type(field_type);
        let attrs = parse_field_attrs(field);

        known_field_names.push(field_name_str.clone());

        let type_name_str = quote!(#field_type).to_string();
        let is_option = matches!(
            kind,
            FieldKind::OptionString
                | FieldKind::OptionI32
                | FieldKind::OptionI64
                | FieldKind::OptionF64
                | FieldKind::OptionBool
        );
        let pii = attrs.pii;

        field_infos.push(quote! {
            a3::schema::FieldInfo {
                name: #field_name_str.to_string(),
                type_name: #type_name_str.to_string(),
                required: !#is_option,
                pii: #pii,
            }
        });

        // Generate validation + sanitization code for this field
        let stmts = gen_field_validation(field_name, &field_name_str, &kind, &attrs);
        validate_stmts.push(stmts);
    }

    let known_fields_array = &known_field_names;

    quote! {
        impl a3::schema::A3Validate for #struct_name {
            fn known_fields() -> &'static [&'static str] {
                &[#(#known_fields_array),*]
            }

            fn validate(&mut self) -> ::std::result::Result<(), ::std::vec::Vec<a3::schema::ValidationError>> {
                let mut errors: ::std::vec::Vec<a3::schema::ValidationError> = ::std::vec::Vec::new();
                #(#validate_stmts)*
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors)
                }
            }
        }

        impl a3::schema::A3SchemaInfo for #struct_name {
            fn schema_info() -> a3::schema::SchemaInfo {
                a3::schema::SchemaInfo {
                    name: stringify!(#struct_name).to_string(),
                    fields: vec![#(#field_infos),*],
                }
            }
        }
    }
}

fn gen_field_validation(
    field_name: &Ident,
    field_name_str: &str,
    kind: &FieldKind,
    attrs: &FieldAttrs,
) -> TokenStream {
    match kind {
        FieldKind::String => gen_string_validation(field_name, field_name_str, attrs, false),
        FieldKind::OptionString => gen_string_validation(field_name, field_name_str, attrs, true),
        FieldKind::I32 => gen_int_validation(field_name, field_name_str, attrs, false, false),
        FieldKind::I64 => gen_int_validation(field_name, field_name_str, attrs, false, true),
        FieldKind::OptionI32 => gen_int_validation(field_name, field_name_str, attrs, true, false),
        FieldKind::OptionI64 => gen_int_validation(field_name, field_name_str, attrs, true, true),
        FieldKind::F64 => gen_float_validation(field_name, field_name_str, attrs, false),
        FieldKind::OptionF64 => gen_float_validation(field_name, field_name_str, attrs, true),
        FieldKind::VecString => gen_vec_string_validation(field_name, field_name_str, attrs),
        FieldKind::VecI32 | FieldKind::VecI64 | FieldKind::VecF64 | FieldKind::VecBool => {
            // Vec of non-string: no special validation beyond existence
            quote! {}
        }
        FieldKind::Bool | FieldKind::OptionBool => quote! {},
        FieldKind::Other => quote! {},
    }
}

fn gen_string_validation(
    field_name: &Ident,
    field_name_str: &str,
    attrs: &FieldAttrs,
    is_option: bool,
) -> TokenStream {
    let mut checks = Vec::new();

    // Sanitization (runs before validation)
    if attrs.sanitize_trim {
        checks.push(quote! { a3::schema::sanitize_trim(val); });
    }
    if attrs.sanitize_lowercase {
        checks.push(quote! { a3::schema::sanitize_lowercase(val); });
    }
    if attrs.sanitize_strip_html {
        checks.push(quote! { a3::schema::sanitize_strip_html(val); });
    }

    // Validation
    if let Some(min) = attrs.min_length {
        checks.push(quote! {
            if val.len() < #min {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at least {} characters", #min),
                    code: "min_length".to_string(),
                });
            }
        });
    }
    if let Some(max) = attrs.max_length {
        checks.push(quote! {
            if val.len() > #max {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at most {} characters", #max),
                    code: "max_length".to_string(),
                });
            }
        });
    }
    if let Some(ref pat) = attrs.pattern {
        checks.push(quote! {
            if !a3::schema::validate_pattern(val, #pat) {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Does not match pattern '{}'", #pat),
                    code: "pattern".to_string(),
                });
            }
        });
    }
    if let Some(ref fmt) = attrs.format {
        let validator = match fmt.as_str() {
            "email" => quote! { a3::schema::validate_email(val) },
            "uuid" => quote! { a3::schema::validate_uuid(val) },
            other => {
                let msg = format!("Unsupported format: {}", other);
                return syn::Error::new_spanned(field_name, msg).to_compile_error();
            }
        };
        let fmt_str = fmt.clone();
        checks.push(quote! {
            if !#validator {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Invalid {} format", #fmt_str),
                    code: "format".to_string(),
                });
            }
        });
    }

    if is_option {
        quote! {
            if let Some(ref mut val) = self.#field_name {
                #(#checks)*
            }
        }
    } else {
        quote! {
            {
                let val = &mut self.#field_name;
                #(#checks)*
            }
        }
    }
}

fn gen_int_validation(
    field_name: &Ident,
    field_name_str: &str,
    attrs: &FieldAttrs,
    is_option: bool,
    _is_i64: bool,
) -> TokenStream {
    let mut checks = Vec::new();

    if let Some(min) = attrs.min_i64 {
        checks.push(quote! {
            if (*val as i64) < #min {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at least {}", #min),
                    code: "min".to_string(),
                });
            }
        });
    }
    if let Some(max) = attrs.max_i64 {
        checks.push(quote! {
            if (*val as i64) > #max {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at most {}", #max),
                    code: "max".to_string(),
                });
            }
        });
    }

    if checks.is_empty() {
        return quote! {};
    }

    if is_option {
        quote! {
            if let Some(ref val) = self.#field_name {
                #(#checks)*
            }
        }
    } else {
        quote! {
            {
                let val = &self.#field_name;
                #(#checks)*
            }
        }
    }
}

fn gen_float_validation(
    field_name: &Ident,
    field_name_str: &str,
    attrs: &FieldAttrs,
    is_option: bool,
) -> TokenStream {
    let mut checks = Vec::new();

    if let Some(min) = attrs.min_f64 {
        checks.push(quote! {
            if *val < #min {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at least {}", #min),
                    code: "min".to_string(),
                });
            }
        });
    }
    if let Some(max) = attrs.max_f64 {
        checks.push(quote! {
            if *val > #max {
                errors.push(a3::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at most {}", #max),
                    code: "max".to_string(),
                });
            }
        });
    }

    if checks.is_empty() {
        return quote! {};
    }

    if is_option {
        quote! {
            if let Some(ref val) = self.#field_name {
                #(#checks)*
            }
        }
    } else {
        quote! {
            {
                let val = &self.#field_name;
                #(#checks)*
            }
        }
    }
}

fn gen_vec_string_validation(
    field_name: &Ident,
    field_name_str: &str,
    attrs: &FieldAttrs,
) -> TokenStream {
    let mut inner_checks = Vec::new();

    if attrs.sanitize_trim {
        inner_checks.push(quote! { a3::schema::sanitize_trim(item); });
    }
    if attrs.sanitize_lowercase {
        inner_checks.push(quote! { a3::schema::sanitize_lowercase(item); });
    }
    if attrs.sanitize_strip_html {
        inner_checks.push(quote! { a3::schema::sanitize_strip_html(item); });
    }

    if let Some(min) = attrs.min_length {
        inner_checks.push(quote! {
            if item.len() < #min {
                errors.push(a3::schema::ValidationError {
                    field: format!("{}[{}]", #field_name_str, __idx),
                    message: format!("Must be at least {} characters", #min),
                    code: "min_length".to_string(),
                });
            }
        });
    }
    if let Some(max) = attrs.max_length {
        inner_checks.push(quote! {
            if item.len() > #max {
                errors.push(a3::schema::ValidationError {
                    field: format!("{}[{}]", #field_name_str, __idx),
                    message: format!("Must be at most {} characters", #max),
                    code: "max_length".to_string(),
                });
            }
        });
    }

    if inner_checks.is_empty() {
        return quote! {};
    }

    quote! {
        for (__idx, item) in self.#field_name.iter_mut().enumerate() {
            #(#inner_checks)*
        }
    }
}

/// Parse all `#[a3(...)]` attributes on a field into `FieldAttrs`.
fn parse_field_attrs(field: &syn::Field) -> FieldAttrs {
    let mut attrs = FieldAttrs::default();

    for attr in &field.attrs {
        if !attr.path().is_ident("a3") {
            continue;
        }

        let _ = attr.parse_nested_meta(|meta| {
            let ident = meta.path.get_ident().map(|i| i.to_string());
            match ident.as_deref() {
                Some("min_length") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Int(n) = lit {
                        attrs.min_length = Some(n.base10_parse()?);
                    }
                }
                Some("max_length") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Int(n) = lit {
                        attrs.max_length = Some(n.base10_parse()?);
                    }
                }
                Some("min") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    match lit {
                        Lit::Int(n) => {
                            attrs.min_i64 = Some(n.base10_parse()?);
                        }
                        Lit::Float(n) => {
                            attrs.min_f64 = Some(n.base10_parse()?);
                        }
                        _ => {}
                    }
                }
                Some("max") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    match lit {
                        Lit::Int(n) => {
                            attrs.max_i64 = Some(n.base10_parse()?);
                        }
                        Lit::Float(n) => {
                            attrs.max_f64 = Some(n.base10_parse()?);
                        }
                        _ => {}
                    }
                }
                Some("pattern") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        attrs.pattern = Some(s.value());
                    }
                }
                Some("format") => {
                    let value = meta.value()?;
                    let lit: Lit = value.parse()?;
                    if let Lit::Str(s) = lit {
                        attrs.format = Some(s.value());
                    }
                }
                Some("pii") => {
                    attrs.pii = true;
                }
                Some("sanitize") => {
                    meta.parse_nested_meta(|nested| {
                        let nested_ident = nested.path.get_ident().map(|i| i.to_string());
                        match nested_ident.as_deref() {
                            Some("trim") => attrs.sanitize_trim = true,
                            Some("lowercase") => attrs.sanitize_lowercase = true,
                            Some("strip_html") => attrs.sanitize_strip_html = true,
                            _ => {}
                        }
                        Ok(())
                    })?;
                }
                _ => {}
            }
            Ok(())
        });
    }

    attrs
}

/// Classify a field type to determine what validation code to generate.
fn classify_type(ty: &Type) -> FieldKind {
    let type_str = quote!(#ty).to_string().replace(' ', "");

    match type_str.as_str() {
        "String" => FieldKind::String,
        "i32" => FieldKind::I32,
        "i64" => FieldKind::I64,
        "f64" => FieldKind::F64,
        "bool" => FieldKind::Bool,
        _ => {
            if type_str.starts_with("Option<") {
                let inner = &type_str[7..type_str.len() - 1];
                match inner {
                    "String" => FieldKind::OptionString,
                    "i32" => FieldKind::OptionI32,
                    "i64" => FieldKind::OptionI64,
                    "f64" => FieldKind::OptionF64,
                    "bool" => FieldKind::OptionBool,
                    _ => FieldKind::Other,
                }
            } else if type_str.starts_with("Vec<") {
                let inner = &type_str[4..type_str.len() - 1];
                match inner {
                    "String" => FieldKind::VecString,
                    "i32" => FieldKind::VecI32,
                    "i64" => FieldKind::VecI64,
                    "f64" => FieldKind::VecF64,
                    "bool" => FieldKind::VecBool,
                    _ => FieldKind::Other,
                }
            } else {
                FieldKind::Other
            }
        }
    }
}
