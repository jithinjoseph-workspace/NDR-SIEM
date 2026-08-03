// NDR Engine — Standard API Response Envelope
// Every endpoint should return Json<ApiResponse<T>> for consistency.

use axum::Json;
use serde::Serialize;
use serde_json::Value;

/// Standard API response envelope.
///
/// Success:  `ApiResponse::ok(payload)`
/// Error:    `ApiResponse::err("reason")`
///
/// Wire format:
///   { "result": true,  "data": <T>,  "error": null }
///   { "result": false, "data": null, "error": "reason" }
#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub result: bool,
    pub data:   Option<T>,
    pub error:  Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<ApiResponse<T>> {
        Json(ApiResponse { result: true, data: Some(data), error: None })
    }

    pub fn err(message: impl Into<String>) -> Json<ApiResponse<T>> {
        Json(ApiResponse { result: false, data: None, error: Some(message.into()) })
    }
}

/// Convenience alias when the data payload is a raw JSON Value.
pub type JsonResponse = Json<ApiResponse<Value>>;

/// Quick helpers — use these in handlers that already build a serde_json::Value.
///
/// ```rust
/// return ok(json!({ "hits": rows }));
/// return err("tenant not found");
/// ```
pub fn ok(data: Value) -> JsonResponse {
    ApiResponse::ok(data)
}

pub fn err_response(message: impl Into<String>) -> JsonResponse {
    ApiResponse::<Value>::err(message)
}
