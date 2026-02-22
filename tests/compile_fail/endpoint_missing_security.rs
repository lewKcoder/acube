use acube::prelude::*;

#[acube_endpoint(GET "/test")]
async fn test_handler(_ctx: AcubeContext) -> AcubeResult<Json<serde_json::Value>, Never> {
    Ok(Json(serde_json::json!({"ok": true})))
}

fn main() {}
