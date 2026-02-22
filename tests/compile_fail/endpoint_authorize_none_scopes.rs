use a3::prelude::*;

#[a3_endpoint(GET "/test")]
#[a3_security(none)]
#[a3_authorize(scopes = ["admin"])]
async fn test_handler(_ctx: A3Context) -> A3Result<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

fn main() {}
