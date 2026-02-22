//! Implementation of `#[a3_endpoint]`, `#[a3_security]`, and `#[a3_rate_limit]`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Ident, ItemFn, Lit, ReturnType, Type};

/// Parsed security declaration.
enum Security {
    None,
    Jwt { scopes: Vec<String> },
}

/// Parsed rate limit declaration.
enum RateLimit {
    None,
    Config { count: u32, per: String },
}

pub fn expand(attr: TokenStream, item: TokenStream) -> Result<TokenStream, syn::Error> {
    // Parse METHOD "path" from attribute args
    let (method_ident, path) = parse_endpoint_attr(attr)?;

    // Parse the annotated function
    let mut func: ItemFn = syn::parse2(item)?;

    // Extract and remove #[a3_security(...)] from the function's attributes
    let security_attr = extract_named_attr(&mut func.attrs, "a3_security");
    let security = match security_attr {
        Some(attr) => parse_security(&attr)?,
        None => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "a³ endpoint requires a security declaration.\n  \
                 Add #[a3_security(jwt, scopes = [...])] or #[a3_security(none)] to explicitly opt out.",
            ));
        }
    };

    // Extract and remove #[a3_rate_limit(...)] from the function's attributes
    let rate_limit_attr = extract_named_attr(&mut func.attrs, "a3_rate_limit");
    let rate_limit = match rate_limit_attr {
        Some(attr) => parse_rate_limit(&attr)?,
        None => RateLimit::Config {
            count: 100,
            per: "per_minute".to_string(),
        }, // default 100/min
    };

    // Extract OpenAPI type information before moving func
    let valid_type = extract_valid_type(&func);
    let (success_status, error_type) = parse_return_type(&func);

    // Generate code
    let fn_name = func.sig.ident.clone();
    let fn_vis = func.vis.clone();
    let handler_name = format_ident!("__a3_impl_{}", fn_name);

    // Rename the original function to the handler name
    let mut handler_fn = func;
    handler_fn.sig.ident = handler_name.clone();

    // Generate the HttpMethod variant
    let method_variant = match method_ident.to_string().as_str() {
        "GET" => quote! { Get },
        "POST" => quote! { Post },
        "PUT" => quote! { Put },
        "PATCH" => quote! { Patch },
        "DELETE" => quote! { Delete },
        other => {
            return Err(syn::Error::new(
                method_ident.span(),
                format!("Unsupported HTTP method: {}", other),
            ));
        }
    };

    // Generate the axum routing function (via a3 re-export)
    let route_fn = match method_ident.to_string().as_str() {
        "GET" => quote! { a3::axum::routing::get },
        "POST" => quote! { a3::axum::routing::post },
        "PUT" => quote! { a3::axum::routing::put },
        "PATCH" => quote! { a3::axum::routing::patch },
        "DELETE" => quote! { a3::axum::routing::delete },
        _ => unreachable!(),
    };

    // Generate security expression
    let security_expr = match security {
        Security::None => quote! { a3::types::EndpointSecurity::None },
        Security::Jwt { scopes } => {
            let scope_strs: Vec<_> = scopes.iter().map(|s| quote!(#s.to_string())).collect();
            quote! { a3::types::EndpointSecurity::Jwt { scopes: vec![#(#scope_strs),*] } }
        }
    };

    // Generate rate limit expression
    let rate_limit_expr = match rate_limit {
        RateLimit::None => quote! { None },
        RateLimit::Config { count, per } => {
            let secs: u64 = match per.as_str() {
                "per_second" => 1,
                "per_minute" => 60,
                "per_hour" => 3600,
                _ => 60,
            };
            quote! {
                Some(a3::types::RateLimitConfig {
                    max_requests: #count,
                    window: ::std::time::Duration::from_secs(#secs),
                })
            }
        }
    };

    // Generate OpenAPI metadata expression
    let request_schema_expr = match &valid_type {
        Some(ty) => quote! { Some(<#ty as a3::schema::A3SchemaInfo>::openapi_schema()) },
        None => quote! { None },
    };
    let request_schema_name_expr = match &valid_type {
        Some(ty) => quote! { Some(stringify!(#ty).to_string()) },
        None => quote! { None },
    };
    let error_responses_expr = match &error_type {
        Some(ty) => quote! { <#ty as a3::error::A3ErrorInfo>::openapi_responses() },
        None => quote! { vec![] },
    };

    Ok(quote! {
        #handler_fn

        /// Create an endpoint registration for this handler.
        #fn_vis fn #fn_name() -> a3::runtime::EndpointRegistration {
            a3::runtime::EndpointRegistration {
                method: a3::types::HttpMethod::#method_variant,
                path: #path.to_string(),
                handler: #route_fn(#handler_name),
                security: #security_expr,
                rate_limit: #rate_limit_expr,
                openapi: Some(a3::runtime::EndpointOpenApi {
                    request_schema: #request_schema_expr,
                    request_schema_name: #request_schema_name_expr,
                    error_responses: #error_responses_expr,
                    success_status: #success_status,
                }),
            }
        }
    })
}

/// Extract the inner type from `Valid<T>` in the function parameters.
fn extract_valid_type(func: &ItemFn) -> Option<Type> {
    for input in &func.sig.inputs {
        if let syn::FnArg::Typed(pat_type) = input {
            if let Type::Path(type_path) = pat_type.ty.as_ref() {
                let last_seg = type_path.path.segments.last()?;
                if last_seg.ident == "Valid" {
                    if let syn::PathArguments::AngleBracketed(args) = &last_seg.arguments {
                        if let Some(syn::GenericArgument::Type(inner)) = args.args.first() {
                            return Some(inner.clone());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parse the return type to extract success status and error type.
/// Returns (success_status, error_type_option).
fn parse_return_type(func: &ItemFn) -> (u16, Option<Type>) {
    let ret = match &func.sig.output {
        ReturnType::Type(_, ty) => ty.as_ref(),
        _ => return (200, None),
    };

    // Expect A3Result<T, E> which is Result<T, E>
    let type_path = match ret {
        Type::Path(tp) => tp,
        _ => return (200, None),
    };

    let last_seg = match type_path.path.segments.last() {
        Some(s) => s,
        None => return (200, None),
    };

    // Accept both A3Result and Result
    if last_seg.ident != "A3Result" && last_seg.ident != "Result" {
        return (200, None);
    }

    let args = match &last_seg.arguments {
        syn::PathArguments::AngleBracketed(a) => a,
        _ => return (200, None),
    };

    let mut iter = args.args.iter();

    // First type arg: success type
    let success_status = match iter.next() {
        Some(syn::GenericArgument::Type(ty)) => {
            if contains_created(ty) { 201 } else { 200 }
        }
        _ => 200,
    };

    // Second type arg: error type
    let error_type = match iter.next() {
        Some(syn::GenericArgument::Type(ty)) => {
            if is_never_type(ty) { None } else { Some(ty.clone()) }
        }
        _ => None,
    };

    (success_status, error_type)
}

/// Check if a type contains `Created<_>`.
fn contains_created(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "Created";
        }
    }
    false
}

/// Check if a type is `Never`.
fn is_never_type(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "Never";
        }
    }
    false
}

/// Parse `METHOD "path"` from the attribute arguments.
fn parse_endpoint_attr(attr: TokenStream) -> Result<(Ident, String), syn::Error> {
    let tokens: Vec<proc_macro2::TokenTree> = attr.into_iter().collect();

    if tokens.len() < 2 {
        return Err(syn::Error::new(
            proc_macro2::Span::call_site(),
            "Expected: #[a3_endpoint(METHOD \"/path\")]",
        ));
    }

    let method = match &tokens[0] {
        proc_macro2::TokenTree::Ident(ident) => ident.clone(),
        _ => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Expected HTTP method (GET, POST, PUT, PATCH, DELETE)",
            ));
        }
    };

    let path = match &tokens[1] {
        proc_macro2::TokenTree::Literal(lit) => {
            let lit_str: Lit = syn::parse2(quote! { #lit })?;
            match lit_str {
                Lit::Str(s) => s.value(),
                _ => {
                    return Err(syn::Error::new(
                        lit.span(),
                        "Expected string literal for path",
                    ));
                }
            }
        }
        _ => {
            return Err(syn::Error::new(
                proc_macro2::Span::call_site(),
                "Expected path string literal",
            ));
        }
    };

    Ok((method, path))
}

/// Find and remove a named attribute from the list.
fn extract_named_attr(attrs: &mut Vec<Attribute>, name: &str) -> Option<Attribute> {
    let idx = attrs.iter().position(|a| a.path().is_ident(name))?;
    Some(attrs.remove(idx))
}

/// Parse `#[a3_security(jwt, scopes = ["..."])]` or `#[a3_security(none)]`.
fn parse_security(attr: &Attribute) -> Result<Security, syn::Error> {
    attr.parse_args_with(|input: syn::parse::ParseStream| {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "none" => Ok(Security::None),
            "jwt" => {
                let mut scopes = Vec::new();
                while !input.is_empty() {
                    input.parse::<syn::Token![,]>()?;
                    let key: Ident = input.parse()?;
                    if key == "scopes" {
                        input.parse::<syn::Token![=]>()?;
                        let content;
                        syn::bracketed!(content in input);
                        while !content.is_empty() {
                            let scope: syn::LitStr = content.parse()?;
                            scopes.push(scope.value());
                            if content.peek(syn::Token![,]) {
                                content.parse::<syn::Token![,]>()?;
                            }
                        }
                    }
                }
                Ok(Security::Jwt { scopes })
            }
            other => Err(syn::Error::new(
                ident.span(),
                format!("Expected 'jwt' or 'none', found '{}'", other),
            )),
        }
    })
}

/// Parse `#[a3_rate_limit(N, per_minute)]` or `#[a3_rate_limit(none)]`.
fn parse_rate_limit(attr: &Attribute) -> Result<RateLimit, syn::Error> {
    attr.parse_args_with(|input: syn::parse::ParseStream| {
        // Check for "none"
        if input.peek(syn::Ident) {
            let ident: Ident = input.fork().parse()?;
            if ident == "none" {
                let _: Ident = input.parse()?;
                return Ok(RateLimit::None);
            }
        }

        let count: syn::LitInt = input.parse()?;
        input.parse::<syn::Token![,]>()?;
        let per: Ident = input.parse()?;

        let per_str = per.to_string();
        if !["per_second", "per_minute", "per_hour"].contains(&per_str.as_str()) {
            return Err(syn::Error::new(
                per.span(),
                "Expected per_second, per_minute, or per_hour",
            ));
        }

        Ok(RateLimit::Config {
            count: count.base10_parse()?,
            per: per_str,
        })
    })
}
