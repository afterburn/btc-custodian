use axum::{
    extract::Request,
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde_json::json;

pub async fn api_key_auth(
    headers: HeaderMap,
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let api_key = std::env::var("API_KEY").expect("API_KEY must be set in .env");

    let auth_header = headers
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok());

    match auth_header {
        Some(key) if key == api_key => Ok(next.run(request).await),
        _ => Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({
                "error": "Unauthorized - Invalid or missing API key"
            })),
        )),
    }
}
