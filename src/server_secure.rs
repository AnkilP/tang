use crate::crypto::{perform_recovery, RecoveryRequest, RecoveryResponse};
use crate::error::TangError;
use crate::jwk::JwkSet;
use crate::keys::KeyManager;
use crate::security::{validate_kid, SecurityConfig};
use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use governor::{Quota, RateLimiter};
use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::{
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{error, info, warn};

type AppRateLimiter = RateLimiter<SocketAddr, governor::state::keyed::DefaultKeyedStateStore<SocketAddr>, governor::clock::DefaultClock>;

#[derive(Clone)]
pub struct AppState {
    pub key_manager: Arc<KeyManager>,
    pub security_config: SecurityConfig,
    pub rate_limiter: Arc<AppRateLimiter>,
}

/// Middleware to add security headers
async fn security_headers_middleware(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Prevent MIME type sniffing
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // Prevent clickjacking
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );

    // Enable XSS protection
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Strict transport security (HSTS) - only if TLS is enabled
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );

    // Content Security Policy - very restrictive
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );

    // Remove server identification
    headers.remove(header::SERVER);

    response
}

/// Middleware for rate limiting per IP
async fn rate_limit_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, AppError> {
    // Extract IP address from socket address
    let ip = request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0)
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    // Check rate limit
    if state.rate_limiter.check_key(&ip).is_err() {
        warn!("Rate limit exceeded for IP: {}", ip);
        return Err(AppError::RateLimitExceeded);
    }

    Ok(next.run(request).await)
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
    info!("Handling advertisement request with kid");

    // Validate kid first
    validate_kid(&kid)?;

    // Verify the signing key exists
    let _signing_key = state.key_manager.load_key(&kid)?;

    // Return the same keys as regular advertisement
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
    info!("Handling recovery request");

    // Validate kid first
    validate_kid(&kid)?;

    // Validate the client's JWK
    request.jwk.validate()?;

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
        return Err(AppError::Tang(TangError::InvalidKeyFormat(
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

/// Create router with all security middleware
pub fn create_secure_router(
    key_manager: Arc<KeyManager>,
    security_config: SecurityConfig,
) -> Router {
    // Create rate limiter with keyed state for per-IP limiting
    let quota = Quota::per_second(
        NonZeroU32::new(security_config.rate_limit_per_second).unwrap(),
    )
    .allow_burst(NonZeroU32::new(security_config.rate_limit_burst).unwrap());

    let rate_limiter = Arc::new(RateLimiter::keyed(quota));

    let state = AppState {
        key_manager,
        security_config: security_config.clone(),
        rate_limiter,
    };

    Router::new()
        .route("/adv", get(advertise_handler))
        .route("/adv/:kid", get(advertise_with_kid_handler))
        .route("/rec/:kid", post(recovery_handler))
        .route("/health", get(health_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn(security_headers_middleware))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(TimeoutLayer::new(security_config.request_timeout)),
        )
        .with_state(state)
}

// Error wrapper for Axum handlers
#[derive(Debug)]
pub enum AppError {
    Tang(TangError),
    RateLimitExceeded,
}

impl From<TangError> for AppError {
    fn from(err: TangError) -> Self {
        AppError::Tang(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Tang(TangError::KeyNotFound(_)) => {
                (StatusCode::NOT_FOUND, "Key not found".to_string())
            }
            AppError::Tang(TangError::InvalidKeyFormat(_)) => {
                (StatusCode::BAD_REQUEST, "Invalid key format".to_string())
            }
            AppError::Tang(TangError::InvalidJwk(_)) => {
                (StatusCode::BAD_REQUEST, "Invalid JWK".to_string())
            }
            AppError::RateLimitExceeded => (
                StatusCode::TOO_MANY_REQUESTS,
                "Rate limit exceeded".to_string(),
            ),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error".to_string(),
            ),
        };

        // Don't leak internal error details in production
        error!("Request error: {:?}", self);

        (status, message).into_response()
    }
}
