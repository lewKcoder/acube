//! Implementation of `#[derive(AcubeSchema)]`.

use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Ident, Lit, Type};

/// Parsed attributes from `#[acube(...)]` on a single field.
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
    one_of: Option<Vec<String>>,
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
    NestedStruct,
    OptionNestedStruct,
    VecNestedStruct,
    Other,
}

pub fn expand(input: &DeriveInput) -> TokenStream {
    let struct_name = &input.ident;

    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return syn::Error::new_spanned(
                    struct_name,
                    "AcubeSchema only supports named fields",
                )
                .to_compile_error();
            }
        },
        _ => {
            return syn::Error::new_spanned(
                struct_name,
                "AcubeSchema can only be derived on structs",
            )
            .to_compile_error();
        }
    };

    let mut validate_stmts = Vec::new();
    let mut known_field_names = Vec::new();
    let mut field_infos = Vec::new();
    let mut openapi_properties = Vec::new();
    let mut openapi_required = Vec::new();

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
                | FieldKind::OptionNestedStruct
        );
        let pii = attrs.pii;

        // Build FieldConstraints
        let min_length_expr = match attrs.min_length {
            Some(v) => quote! { Some(#v) },
            None => quote! { None },
        };
        let max_length_expr = match attrs.max_length {
            Some(v) => quote! { Some(#v) },
            None => quote! { None },
        };
        let pattern_expr = match &attrs.pattern {
            Some(v) => quote! { Some(#v.to_string()) },
            None => quote! { None },
        };
        let format_expr = match &attrs.format {
            Some(v) => quote! { Some(#v.to_string()) },
            None => quote! { None },
        };
        let min_expr = match (attrs.min_i64, attrs.min_f64) {
            (Some(v), _) => quote! { Some(#v as f64) },
            (_, Some(v)) => quote! { Some(#v) },
            _ => quote! { None },
        };
        let max_expr = match (attrs.max_i64, attrs.max_f64) {
            (Some(v), _) => quote! { Some(#v as f64) },
            (_, Some(v)) => quote! { Some(#v) },
            _ => quote! { None },
        };

        field_infos.push(quote! {
            acube::schema::FieldInfo {
                name: #field_name_str.to_string(),
                type_name: #type_name_str.to_string(),
                required: !#is_option,
                pii: #pii,
                constraints: acube::schema::FieldConstraints {
                    min_length: #min_length_expr,
                    max_length: #max_length_expr,
                    pattern: #pattern_expr,
                    format: #format_expr,
                    min: #min_expr,
                    max: #max_expr,
                },
            }
        });

        // Collect OpenAPI property info
        let prop_token = gen_openapi_property(&field_name_str, &kind, &attrs);
        openapi_properties.push(prop_token);
        if !is_option {
            openapi_required.push(field_name_str.clone());
        }

        // Generate validation + sanitization code for this field
        let stmts = gen_field_validation(field_name, &field_name_str, &kind, &attrs);
        validate_stmts.push(stmts);
    }

    let known_fields_array = &known_field_names;

    quote! {
        impl acube::schema::AcubeValidate for #struct_name {
            fn known_fields() -> &'static [&'static str] {
                &[#(#known_fields_array),*]
            }

            fn validate(&mut self) -> ::std::result::Result<(), ::std::vec::Vec<acube::schema::ValidationError>> {
                let mut errors: ::std::vec::Vec<acube::schema::ValidationError> = ::std::vec::Vec::new();
                #(#validate_stmts)*
                if errors.is_empty() {
                    Ok(())
                } else {
                    Err(errors)
                }
            }
        }

        impl acube::schema::AcubeSchemaInfo for #struct_name {
            fn schema_info() -> acube::schema::SchemaInfo {
                acube::schema::SchemaInfo {
                    name: stringify!(#struct_name).to_string(),
                    fields: vec![#(#field_infos),*],
                }
            }

            fn openapi_schema() -> serde_json::Value {
                let mut properties = serde_json::Map::new();
                #(#openapi_properties)*
                let required: Vec<serde_json::Value> = vec![#(serde_json::Value::String(#openapi_required.to_string())),*];
                let mut schema = serde_json::Map::new();
                schema.insert("type".to_string(), serde_json::Value::String("object".to_string()));
                schema.insert("properties".to_string(), serde_json::Value::Object(properties));
                if !required.is_empty() {
                    schema.insert("required".to_string(), serde_json::Value::Array(required));
                }
                schema.insert("additionalProperties".to_string(), serde_json::Value::Bool(false));
                serde_json::Value::Object(schema)
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
        FieldKind::NestedStruct => gen_nested_validation(field_name, field_name_str, false, false),
        FieldKind::OptionNestedStruct => {
            gen_nested_validation(field_name, field_name_str, true, false)
        }
        FieldKind::VecNestedStruct => {
            gen_nested_validation(field_name, field_name_str, false, true)
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
        checks.push(quote! { acube::schema::sanitize_trim(val); });
    }
    if attrs.sanitize_lowercase {
        checks.push(quote! { acube::schema::sanitize_lowercase(val); });
    }
    if attrs.sanitize_strip_html {
        checks.push(quote! { acube::schema::sanitize_strip_html(val); });
    }

    // Validation
    if let Some(min) = attrs.min_length {
        checks.push(quote! {
            if val.len() < #min {
                errors.push(acube::schema::ValidationError {
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
                errors.push(acube::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Must be at most {} characters", #max),
                    code: "max_length".to_string(),
                });
            }
        });
    }
    if let Some(ref pat) = attrs.pattern {
        checks.push(quote! {
            if !acube::schema::validate_pattern(val, #pat) {
                errors.push(acube::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Does not match pattern '{}'", #pat),
                    code: "pattern".to_string(),
                });
            }
        });
    }
    if let Some(ref fmt) = attrs.format {
        let validator = match fmt.as_str() {
            "email" => quote! { acube::schema::validate_email(val) },
            "url" => quote! { acube::schema::validate_url(val) },
            "uuid" => quote! { acube::schema::validate_uuid(val) },
            other => {
                let msg = format!("Unsupported format: {}", other);
                return syn::Error::new_spanned(field_name, msg).to_compile_error();
            }
        };
        let fmt_str = fmt.clone();
        checks.push(quote! {
            if !#validator {
                errors.push(acube::schema::ValidationError {
                    field: #field_name_str.to_string(),
                    message: format!("Invalid {} format", #fmt_str),
                    code: "format".to_string(),
                });
            }
        });
    }

    if let Some(ref values) = attrs.one_of {
        let allowed: Vec<&str> = values.iter().map(|s| s.as_str()).collect();
        checks.push(quote! {
            {
                let __acube_allowed: &[&str] = &[#(#allowed),*];
                if !__acube_allowed.contains(&val.as_str()) {
                    errors.push(acube::schema::ValidationError {
                        field: #field_name_str.to_string(),
                        message: format!("Must be one of: {}", __acube_allowed.join(", ")),
                        code: "one_of".to_string(),
                    });
                }
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
                errors.push(acube::schema::ValidationError {
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
                errors.push(acube::schema::ValidationError {
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
                errors.push(acube::schema::ValidationError {
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
                errors.push(acube::schema::ValidationError {
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
        inner_checks.push(quote! { acube::schema::sanitize_trim(item); });
    }
    if attrs.sanitize_lowercase {
        inner_checks.push(quote! { acube::schema::sanitize_lowercase(item); });
    }
    if attrs.sanitize_strip_html {
        inner_checks.push(quote! { acube::schema::sanitize_strip_html(item); });
    }

    if let Some(min) = attrs.min_length {
        inner_checks.push(quote! {
            if item.len() < #min {
                errors.push(acube::schema::ValidationError {
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
                errors.push(acube::schema::ValidationError {
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

fn gen_nested_validation(
    field_name: &Ident,
    field_name_str: &str,
    is_option: bool,
    is_vec: bool,
) -> TokenStream {
    if is_vec {
        quote! {
            for (__idx, item) in self.#field_name.iter_mut().enumerate() {
                if let Err(nested_errors) = item.validate() {
                    for mut e in nested_errors {
                        e.field = format!("{}[{}].{}", #field_name_str, __idx, e.field);
                        errors.push(e);
                    }
                }
            }
        }
    } else if is_option {
        quote! {
            if let Some(ref mut item) = self.#field_name {
                if let Err(nested_errors) = item.validate() {
                    for mut e in nested_errors {
                        e.field = format!("{}.{}", #field_name_str, e.field);
                        errors.push(e);
                    }
                }
            }
        }
    } else {
        quote! {
            {
                let item = &mut self.#field_name;
                if let Err(nested_errors) = item.validate() {
                    for mut e in nested_errors {
                        e.field = format!("{}.{}", #field_name_str, e.field);
                        errors.push(e);
                    }
                }
            }
        }
    }
}

/// Generate a token stream that inserts an OpenAPI property for a field.
fn gen_openapi_property(field_name_str: &str, kind: &FieldKind, attrs: &FieldAttrs) -> TokenStream {
    // Determine base OpenAPI type and format
    let (oa_type, oa_format, is_array) = match kind {
        FieldKind::String | FieldKind::OptionString => ("string", None, false),
        FieldKind::I32 | FieldKind::OptionI32 => ("integer", Some("int32"), false),
        FieldKind::I64 | FieldKind::OptionI64 => ("integer", Some("int64"), false),
        FieldKind::F64 | FieldKind::OptionF64 => ("number", Some("double"), false),
        FieldKind::Bool | FieldKind::OptionBool => ("boolean", None, false),
        FieldKind::VecString => ("string", None, true),
        FieldKind::VecI32 => ("integer", Some("int32"), true),
        FieldKind::VecI64 => ("integer", Some("int64"), true),
        FieldKind::VecF64 => ("number", Some("double"), true),
        FieldKind::VecBool => ("boolean", None, true),
        FieldKind::NestedStruct | FieldKind::OptionNestedStruct => ("object", None, false),
        FieldKind::VecNestedStruct => ("object", None, true),
        FieldKind::Other => ("object", None, false),
    };

    // Build constraint insertions
    let mut constraint_stmts = Vec::new();

    if let Some(min_len) = attrs.min_length {
        constraint_stmts.push(quote! {
            prop.insert("minLength".to_string(), serde_json::Value::Number(serde_json::Number::from(#min_len)));
        });
    }
    if let Some(max_len) = attrs.max_length {
        constraint_stmts.push(quote! {
            prop.insert("maxLength".to_string(), serde_json::Value::Number(serde_json::Number::from(#max_len)));
        });
    }
    if let Some(ref pattern) = attrs.pattern {
        constraint_stmts.push(quote! {
            prop.insert("pattern".to_string(), serde_json::Value::String(#pattern.to_string()));
        });
    }
    // Use constraint format (email/uuid) which overrides type-level format
    if let Some(ref fmt) = attrs.format {
        constraint_stmts.push(quote! {
            prop.insert("format".to_string(), serde_json::Value::String(#fmt.to_string()));
        });
    }
    if let Some(min_i) = attrs.min_i64 {
        let min_f = min_i as f64;
        constraint_stmts.push(quote! {
            prop.insert("minimum".to_string(), serde_json::json!(#min_f));
        });
    }
    if let Some(min_f) = attrs.min_f64 {
        constraint_stmts.push(quote! {
            prop.insert("minimum".to_string(), serde_json::json!(#min_f));
        });
    }
    if let Some(max_i) = attrs.max_i64 {
        let max_f = max_i as f64;
        constraint_stmts.push(quote! {
            prop.insert("maximum".to_string(), serde_json::json!(#max_f));
        });
    }
    if let Some(max_f) = attrs.max_f64 {
        constraint_stmts.push(quote! {
            prop.insert("maximum".to_string(), serde_json::json!(#max_f));
        });
    }
    if let Some(ref values) = attrs.one_of {
        let vals: Vec<&str> = values.iter().map(|v| v.as_str()).collect();
        constraint_stmts.push(quote! {
            prop.insert("enum".to_string(), serde_json::Value::Array(
                vec![#(serde_json::Value::String(#vals.to_string())),*]
            ));
        });
    }

    if is_array {
        // Array type: { "type": "array", "items": { "type": "...", ... } }
        let format_stmt = match oa_format {
            Some(fmt) => quote! {
                items.insert("format".to_string(), serde_json::Value::String(#fmt.to_string()));
            },
            None => quote! {},
        };
        quote! {
            {
                let mut prop = serde_json::Map::new();
                prop.insert("type".to_string(), serde_json::Value::String("array".to_string()));
                let mut items = serde_json::Map::new();
                items.insert("type".to_string(), serde_json::Value::String(#oa_type.to_string()));
                #format_stmt
                #(#constraint_stmts)*
                prop.insert("items".to_string(), serde_json::Value::Object(items));
                properties.insert(#field_name_str.to_string(), serde_json::Value::Object(prop));
            }
        }
    } else {
        let format_stmt = match (oa_format, &attrs.format) {
            // If attrs.format is set, it's already handled in constraint_stmts
            (_, Some(_)) => quote! {},
            (Some(fmt), None) => quote! {
                prop.insert("format".to_string(), serde_json::Value::String(#fmt.to_string()));
            },
            (None, None) => quote! {},
        };
        quote! {
            {
                let mut prop = serde_json::Map::new();
                prop.insert("type".to_string(), serde_json::Value::String(#oa_type.to_string()));
                #format_stmt
                #(#constraint_stmts)*
                properties.insert(#field_name_str.to_string(), serde_json::Value::Object(prop));
            }
        }
    }
}

/// Parse all `#[acube(...)]` attributes on a field into `FieldAttrs`.
fn parse_field_attrs(field: &syn::Field) -> FieldAttrs {
    let mut attrs = FieldAttrs::default();

    for attr in &field.attrs {
        if !attr.path().is_ident("acube") {
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
                Some("one_of") => {
                    let value = meta.value()?;
                    let content;
                    syn::bracketed!(content in value);
                    let mut values = Vec::new();
                    while !content.is_empty() {
                        let lit: syn::LitStr = content.parse()?;
                        values.push(lit.value());
                        if content.peek(syn::Token![,]) {
                            content.parse::<syn::Token![,]>()?;
                        }
                    }
                    attrs.one_of = Some(values);
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
                    _ => {
                        if !inner.contains('<') {
                            FieldKind::OptionNestedStruct
                        } else {
                            FieldKind::Other
                        }
                    }
                }
            } else if type_str.starts_with("Vec<") {
                let inner = &type_str[4..type_str.len() - 1];
                match inner {
                    "String" => FieldKind::VecString,
                    "i32" => FieldKind::VecI32,
                    "i64" => FieldKind::VecI64,
                    "f64" => FieldKind::VecF64,
                    "bool" => FieldKind::VecBool,
                    _ => {
                        if !inner.contains('<') {
                            FieldKind::VecNestedStruct
                        } else {
                            FieldKind::Other
                        }
                    }
                }
            } else if !type_str.contains('<') {
                FieldKind::NestedStruct
            } else {
                FieldKind::Other
            }
        }
    }
}
