use crate::crypto::{perform_recovery, RecoveryRequest, RecoveryResponse};
use crate::error::TangError;
use crate::jwk::JwkSet;
use crate::keys::KeyManager;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::sync::Arc;
use tracing::{error, info};

#[derive(Clone)]
pub struct AppState {
    pub key_manager: Arc<KeyManager>,
}

/// Handler for GET /adv - advertise all public keys
async fn advertise_handler(
    State(state): State<AppState>,
) -> std::result::Result<Json<JwkSet>, AppError> {
    info!("Handling advertisement request");

    let signing_keys = state.key_manager.get_signing_keys()?;
    let exchange_keys = state.key_manager.get_exchange_keys()?;

    let mut jwk_set = JwkSet::new();
    for key in signing_keys {
        jwk_set.add_key(key);
    }
    for key in exchange_keys {
        jwk_set.add_key(key);
    }

    Ok(Json(jwk_set))
}

/// Handler for GET /adv/{kid} - advertise keys using specific signing key
async fn advertise_with_kid_handler(
    Path(kid): Path<String>,
    State(state): State<AppState>,
) -> std::result::Result<Json<JwkSet>, AppError> {
    info!("Handling advertisement request with kid: {}", kid);

    // Verify the signing key exists
    let _signing_key = state.key_manager.load_key(&kid)?;

    // Return the same keys as regular advertisement
    // In a full implementation, this would sign the JWK set with the specified key
    let signing_keys = state.key_manager.get_signing_keys()?;
    let exchange_keys = state.key_manager.get_exchange_keys()?;

    let mut jwk_set = JwkSet::new();
    for key in signing_keys {
        jwk_set.add_key(key);
    }
    for key in exchange_keys {
        jwk_set.add_key(key);
    }

    Ok(Json(jwk_set))
}

/// Handler for POST /rec/{kid} - perform key recovery
async fn recovery_handler(
    Path(kid): Path<String>,
    State(state): State<AppState>,
    Json(request): Json<RecoveryRequest>,
) -> std::result::Result<Json<RecoveryResponse>, AppError> {
    info!("Handling recovery request with kid: {}", kid);

    // Load the server's exchange key
    let server_key = state.key_manager.load_key(&kid)?;

    // Verify it's an exchange key
    if server_key
        .other
        .get("use")
        .and_then(|v| v.as_str())
        .map(|u| u != "enc")
        .unwrap_or(true)
    {
        return Err(AppError(TangError::InvalidKeyFormat(
            "Key is not an exchange key".to_string(),
        )));
    }

    // Perform the recovery operation
    let result_jwk = perform_recovery(&server_key, &request.jwk)?;

    Ok(Json(RecoveryResponse { jwk: result_jwk }))
}

/// Health check endpoint
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

pub fn create_router(key_manager: Arc<KeyManager>) -> Router {
    let state = AppState { key_manager };

    Router::new()
        .route("/adv", get(advertise_handler))
        .route("/adv/:kid", get(advertise_with_kid_handler))
        .route("/rec/:kid", post(recovery_handler))
        .route("/health", get(health_handler))
        .with_state(state)
}

// Error wrapper for Axum handlers
pub struct AppError(TangError);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self.0 {
            TangError::KeyNotFound(_) => (StatusCode::NOT_FOUND, self.0.to_string()),
            TangError::InvalidKeyFormat(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            TangError::InvalidJwk(_) => (StatusCode::BAD_REQUEST, self.0.to_string()),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        error!("Request error: {}", message);
        (status, message).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<TangError>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
