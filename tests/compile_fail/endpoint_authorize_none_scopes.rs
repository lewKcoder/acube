use acube::prelude::*;

#[acube_endpoint(GET "/test")]
#[acube_security(none)]
#[acube_authorize(scopes = ["admin"])]
async fn test_handler(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

fn main() {}
