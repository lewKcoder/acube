//! Implementation of `#[acube_endpoint]`, `#[acube_security]`, `#[acube_authorize]`, and `#[acube_rate_limit]`.

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::{Attribute, Ident, ItemFn, Lit, ReturnType, Type};

/// Parsed security declaration.
enum Security {
    None,
    Jwt,
}

/// Parsed authorization declaration.
enum Authorization {
    Public,
    Authenticated,
    Scopes(Vec<String>),
    Role(String),
    Custom(String),
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

    // Extract and remove #[acube_security(...)] from the function's attributes
    let security_attr = extract_named_attr(&mut func.attrs, "acube_security");
    let security = match security_attr {
        Some(attr) => parse_security(&attr)?,
        None => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "acube endpoint requires a security declaration.\n  \
                 Add #[acube_security(jwt)] or #[acube_security(none)] to explicitly opt out.",
            ));
        }
    };

    // Extract and remove #[acube_authorize(...)] from the function's attributes
    let authorize_attr = extract_named_attr(&mut func.attrs, "acube_authorize");
    let authorization = match authorize_attr {
        Some(attr) => parse_authorize(&attr)?,
        None => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "acube endpoint requires an authorization declaration.\n  \
                 Add #[acube_authorize(scopes = [...])] or #[acube_authorize(public)] to explicitly opt out.",
            ));
        }
    };

    // Consistency checks between security and authorization
    match (&security, &authorization) {
        (Security::None, Authorization::Scopes(_)) => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "Cannot use #[acube_authorize(scopes = [...])] with #[acube_security(none)]. \
                 Use #[acube_security(jwt)] for scope-protected endpoints.",
            ));
        }
        (Security::None, Authorization::Role(_)) => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "Cannot use #[acube_authorize(role = \"...\")] with #[acube_security(none)]. \
                 Use #[acube_security(jwt)] for role-protected endpoints.",
            ));
        }
        (Security::None, Authorization::Authenticated) => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "Cannot use #[acube_authorize(authenticated)] with #[acube_security(none)]. \
                 Use #[acube_security(jwt)] for authenticated endpoints.",
            ));
        }
        (Security::None, Authorization::Custom(_)) => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "Cannot use #[acube_authorize(custom = \"...\")] with #[acube_security(none)]. \
                 Custom authorization requires #[acube_security(jwt)].",
            ));
        }
        (Security::Jwt, Authorization::Public) => {
            return Err(syn::Error::new_spanned(
                &func.sig.ident,
                "Cannot use #[acube_authorize(public)] with #[acube_security(jwt)]. \
                 Use #[acube_security(none)] for public endpoints.",
            ));
        }
        _ => {}
    }

    // Extract and remove #[acube_rate_limit(...)] from the function's attributes
    let rate_limit_attr = extract_named_attr(&mut func.attrs, "acube_rate_limit");
    let rate_limit = match rate_limit_attr {
        Some(attr) => parse_rate_limit(&attr)?,
        None => RateLimit::Config {
            count: 100,
            per: "per_minute".to_string(),
        }, // default 100/min
    };

    // Extract OpenAPI type information before moving func
    let valid_type = extract_valid_type(&func);
    let (success_status, error_type, has_content) = parse_return_type(&func);

    // Generate code
    let fn_name = func.sig.ident.clone();
    let fn_vis = func.vis.clone();
    let handler_name = format_ident!("__acube_impl_{}", fn_name);

    let mut handler_fn = func;

    // For custom auth, rename to __acube_inner_ and generate a wrapper __acube_impl_
    // For regular auth, rename to __acube_impl_ directly
    let custom_wrapper = if let Authorization::Custom(ref func_name) = authorization {
        let custom_fn = format_ident!("{}", func_name);
        let inner_name = format_ident!("__acube_inner_{}", fn_name);
        handler_fn.sig.ident = inner_name.clone();

        // Build wrapper params and forward args
        let mut wrapper_params = Vec::new();
        let mut forward_args = Vec::new();
        let mut ctx_arg = None;

        for (i, arg) in handler_fn.sig.inputs.iter().enumerate() {
            if let syn::FnArg::Typed(pt) = arg {
                let ty = &pt.ty;
                let arg_name = format_ident!("__acube_param_{}", i);
                wrapper_params.push(quote! { #arg_name: #ty });
                forward_args.push(quote! { #arg_name });
                if i == 0 {
                    ctx_arg = Some(arg_name);
                }
            }
        }

        let ctx_arg = ctx_arg.expect("endpoint must have at least one parameter (AcubeContext)");

        quote! {
            async fn #handler_name(#(#wrapper_params),*) -> ::axum::response::Response {
                use ::axum::response::IntoResponse;
                if let Err(__acube_auth_err) = #custom_fn(&#ctx_arg).await {
                    return __acube_auth_err.into_response();
                }
                match #inner_name(#(#forward_args),*).await {
                    Ok(__acube_ok) => __acube_ok.into_response(),
                    Err(__acube_err) => __acube_err.into_response(),
                }
            }
        }
    } else {
        handler_fn.sig.ident = handler_name.clone();
        quote! {}
    };

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

    // Generate the axum routing function (via acube re-export)
    let route_fn = match method_ident.to_string().as_str() {
        "GET" => quote! { acube::axum::routing::get },
        "POST" => quote! { acube::axum::routing::post },
        "PUT" => quote! { acube::axum::routing::put },
        "PATCH" => quote! { acube::axum::routing::patch },
        "DELETE" => quote! { acube::axum::routing::delete },
        _ => unreachable!(),
    };

    // Generate security expression
    let security_expr = match security {
        Security::None => quote! { acube::types::EndpointSecurity::None },
        Security::Jwt => quote! { acube::types::EndpointSecurity::Jwt },
    };

    // Generate authorization expression
    let authorization_expr = match &authorization {
        Authorization::Public => quote! { acube::types::EndpointAuthorization::Public },
        Authorization::Authenticated => {
            quote! { acube::types::EndpointAuthorization::Authenticated }
        }
        Authorization::Scopes(scopes) => {
            let scope_strs: Vec<_> = scopes.iter().map(|s| quote!(#s.to_string())).collect();
            quote! { acube::types::EndpointAuthorization::Scopes(vec![#(#scope_strs),*]) }
        }
        Authorization::Role(role) => {
            quote! { acube::types::EndpointAuthorization::Role(#role.to_string()) }
        }
        Authorization::Custom(_) => {
            // Custom auth is checked in the handler wrapper; middleware just verifies JWT
            quote! { acube::types::EndpointAuthorization::Authenticated }
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
                Some(acube::types::RateLimitConfig {
                    max_requests: #count,
                    window: ::std::time::Duration::from_secs(#secs),
                })
            }
        }
    };

    // Generate OpenAPI metadata expression
    let request_schema_expr = match &valid_type {
        Some(ty) => quote! { Some(<#ty as acube::schema::AcubeSchemaInfo>::openapi_schema()) },
        None => quote! { None },
    };
    let request_schema_name_expr = match &valid_type {
        Some(ty) => quote! { Some(stringify!(#ty).to_string()) },
        None => quote! { None },
    };
    let error_responses_expr = match &error_type {
        Some(ty) => quote! { <#ty as acube::error::AcubeErrorInfo>::openapi_responses() },
        None => quote! { vec![] },
    };

    let content_type_expr = if has_content {
        quote! { Some("application/json".to_string()) }
    } else {
        quote! { None }
    };

    Ok(quote! {
        #handler_fn

        #custom_wrapper

        /// Create an endpoint registration for this handler.
        #fn_vis fn #fn_name() -> acube::runtime::EndpointRegistration {
            acube::runtime::EndpointRegistration {
                method: acube::types::HttpMethod::#method_variant,
                path: #path.to_string(),
                handler: #route_fn(#handler_name),
                security: #security_expr,
                authorization: #authorization_expr,
                rate_limit: #rate_limit_expr,
                openapi: Some(acube::runtime::EndpointOpenApi {
                    request_schema: #request_schema_expr,
                    request_schema_name: #request_schema_name_expr,
                    error_responses: #error_responses_expr,
                    success_status: #success_status,
                    content_type: #content_type_expr,
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

/// Parse the return type to extract success status, error type, and whether it has content.
/// Returns (success_status, error_type_option, has_content).
fn parse_return_type(func: &ItemFn) -> (u16, Option<Type>, bool) {
    let ret = match &func.sig.output {
        ReturnType::Type(_, ty) => ty.as_ref(),
        _ => return (200, None, true),
    };

    // Expect AcubeResult<T, E> which is Result<T, E>
    let type_path = match ret {
        Type::Path(tp) => tp,
        _ => return (200, None, true),
    };

    let last_seg = match type_path.path.segments.last() {
        Some(s) => s,
        None => return (200, None, true),
    };

    // Accept both AcubeResult and Result
    if last_seg.ident != "AcubeResult" && last_seg.ident != "Result" {
        return (200, None, true);
    }

    let args = match &last_seg.arguments {
        syn::PathArguments::AngleBracketed(a) => a,
        _ => return (200, None, true),
    };

    let mut iter = args.args.iter();

    // First type arg: success type
    let (success_status, has_content) = match iter.next() {
        Some(syn::GenericArgument::Type(ty)) => {
            if contains_created(ty) {
                (201, true)
            } else if contains_no_content(ty) {
                (204, false)
            } else {
                (200, true)
            }
        }
        _ => (200, true),
    };

    // Second type arg: error type
    let error_type = match iter.next() {
        Some(syn::GenericArgument::Type(ty)) => {
            if is_never_type(ty) { None } else { Some(ty.clone()) }
        }
        _ => None,
    };

    (success_status, error_type, has_content)
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

/// Check if a type is `NoContent`.
fn contains_no_content(ty: &Type) -> bool {
    if let Type::Path(tp) = ty {
        if let Some(seg) = tp.path.segments.last() {
            return seg.ident == "NoContent";
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
            "Expected: #[acube_endpoint(METHOD \"/path\")]",
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

/// Parse `#[acube_security(jwt)]` or `#[acube_security(none)]`.
///
/// Produces a helpful error if the legacy `scopes = [...]` syntax is used.
fn parse_security(attr: &Attribute) -> Result<Security, syn::Error> {
    attr.parse_args_with(|input: syn::parse::ParseStream| {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "none" => Ok(Security::None),
            "jwt" => {
                // Check for legacy scopes syntax and produce helpful error
                if !input.is_empty() {
                    if input.peek(syn::Token![,]) {
                        let comma_span = input.parse::<syn::Token![,]>()?.span;
                        if input.peek(syn::Ident) {
                            let key: Ident = input.fork().parse()?;
                            if key == "scopes" {
                                return Err(syn::Error::new(
                                    comma_span,
                                    "Scopes have moved to #[acube_authorize(scopes = [...])]. \
                                     Use #[acube_security(jwt)] for authentication only.",
                                ));
                            }
                        }
                    }
                }
                Ok(Security::Jwt)
            }
            other => Err(syn::Error::new(
                ident.span(),
                format!("Expected 'jwt' or 'none', found '{}'", other),
            )),
        }
    })
}

/// Parse `#[acube_authorize(public)]`, `#[acube_authorize(authenticated)]`,
/// `#[acube_authorize(scopes = ["..."])]`, or `#[acube_authorize(role = "...")]`.
fn parse_authorize(attr: &Attribute) -> Result<Authorization, syn::Error> {
    attr.parse_args_with(|input: syn::parse::ParseStream| {
        let ident: Ident = input.parse()?;
        match ident.to_string().as_str() {
            "public" => Ok(Authorization::Public),
            "authenticated" => Ok(Authorization::Authenticated),
            "scopes" => {
                input.parse::<syn::Token![=]>()?;
                let content;
                syn::bracketed!(content in input);
                let mut scopes = Vec::new();
                while !content.is_empty() {
                    let scope: syn::LitStr = content.parse()?;
                    scopes.push(scope.value());
                    if content.peek(syn::Token![,]) {
                        content.parse::<syn::Token![,]>()?;
                    }
                }
                Ok(Authorization::Scopes(scopes))
            }
            "role" => {
                input.parse::<syn::Token![=]>()?;
                let role: syn::LitStr = input.parse()?;
                Ok(Authorization::Role(role.value()))
            }
            "custom" => {
                input.parse::<syn::Token![=]>()?;
                let func: syn::LitStr = input.parse()?;
                Ok(Authorization::Custom(func.value()))
            }
            other => Err(syn::Error::new(
                ident.span(),
                format!(
                    "Expected 'public', 'authenticated', 'scopes', 'role', or 'custom', found '{}'",
                    other
                ),
            )),
        }
    })
}

/// Parse `#[acube_rate_limit(N, per_minute)]` or `#[acube_rate_limit(none)]`.
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
