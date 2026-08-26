use actix_web::{HttpResponse, http::StatusCode};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("storage error: {0}")]
    Storage(#[from] object_store::Error),

    #[error("unsupported or unrecognised symbol file: {0}")]
    UnrecognisedFormat(String),

    #[error("authentication failed: {0}")]
    Unauthenticated(String),

    #[error("not authorized: {0}")]
    Forbidden(String),

    #[error("not found")]
    NotFound,

    #[error("invalid request: {0}")]
    BadRequest(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("{0}")]
    Internal(String),
}

impl Error {
    fn status(&self) -> StatusCode {
        match self {
            Error::UnrecognisedFormat(_) | Error::BadRequest(_) => StatusCode::BAD_REQUEST,
            Error::Unauthenticated(_) => StatusCode::UNAUTHORIZED,
            Error::Forbidden(_) => StatusCode::FORBIDDEN,
            Error::NotFound => StatusCode::NOT_FOUND,
            Error::Upstream(_) => StatusCode::BAD_GATEWAY,
            Error::Config(_) | Error::Storage(_) | Error::Internal(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
        }
    }
}

impl actix_web::ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        self.status()
    }

    fn error_response(&self) -> HttpResponse {
        // Storage/internal details stay out of responses; they're logged by the
        // handlers instead.
        let message = match self {
            Error::Storage(_) | Error::Internal(_) | Error::Config(_) => {
                "internal error".to_string()
            }
            other => other.to_string(),
        };
        HttpResponse::build(self.status()).json(serde_json::json!({
            "error": message,
        }))
    }
}
