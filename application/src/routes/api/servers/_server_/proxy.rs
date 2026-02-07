use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod create {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use axum::Json;
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use tokio::fs;
    use tokio::process::Command;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct CreateProxyRequest {
        domain: String,
        ip: String,
        port: String,
        #[serde(default)]
        ssl: bool,
        #[serde(default)]
        use_lets_encrypt: bool,
        #[serde(default)]
        client_email: Option<String>,
        #[serde(default)]
        ssl_cert: Option<String>,
        #[serde(default)]
        ssl_key: Option<String>,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/create", responses(
        (status = ACCEPTED, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(
        _server: GetServer,
        Json(data): Json<CreateProxyRequest>,
    ) -> ApiResponseResult {
        let sites_available = format!("/etc/nginx/sites-available/{}_{}.conf", data.domain, data.port);
        let sites_enabled = format!("/etc/nginx/sites-enabled/{}_{}.conf", data.domain, data.port);

        // Initial HTTP-only config (for ACME challenge or non-SSL)
        let nginx_config = format!(
            r#"server {{
    listen 80;
    server_name {domain};

    location / {{
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass http://{ip}:{port};
    }}

    location /.well-known/acme-challenge/ {{
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:81$request_uri;
    }}
}}"#,
            domain = data.domain,
            ip = data.ip,
            port = data.port
        );

        // Write initial config
        if let Err(e) = fs::write(&sites_available, &nginx_config).await {
            tracing::error!(
                "failed to write nginx config {}_{}.conf: {}",
                data.domain, data.port, e
            );
            return ApiResponse::error("Failed to write nginx config")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .ok();
        }

        // Create symlink
        if !Path::new(&sites_enabled).exists() {
            let _ = Command::new("ln")
                .args(["-s", &sites_available, &sites_enabled])
                .output()
                .await;
        }

        // Reload nginx
        let _ = Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .await;

        // Handle SSL
        if data.ssl {
            let cert_dir = format!("/srv/server_certs/{}", data.domain);
            let cert_path = format!("{}/cert.pem", cert_dir);
            let key_path = format!("{}/key.pem", cert_dir);

            // Create cert directory
            if let Err(e) = fs::create_dir_all(&cert_dir).await {
                tracing::error!(
                    "failed to create cert directory {}: {}",
                    cert_dir, e
                );
                return ApiResponse::error("Failed to create certificate directory")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            if data.use_lets_encrypt {
                // For Let's Encrypt, we would need an ACME client
                // For now, return an error suggesting manual setup or custom certs
                tracing::warn!(
                    "Let's Encrypt automatic certificate generation is not yet implemented in Rust Wings. \
                     Please use custom SSL certificates or generate certs manually with certbot."
                );
                return ApiResponse::error(
                    "Let's Encrypt not yet implemented. Use custom SSL certificates instead.",
                )
                .with_status(StatusCode::NOT_IMPLEMENTED)
                .ok();
            } else {
                // Custom SSL certificates
                let ssl_cert = match &data.ssl_cert {
                    Some(cert) => cert,
                    None => {
                        return ApiResponse::error("SSL certificate required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                let ssl_key = match &data.ssl_key {
                    Some(key) => key,
                    None => {
                        return ApiResponse::error("SSL key required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                // Write certificate files
                if let Err(e) = fs::write(&cert_path, ssl_cert).await {
                    tracing::error!("failed to write cert {}: {}", cert_path, e);
                    return ApiResponse::error("Failed to save certificate")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok();
                }

                if let Err(e) = fs::write(&key_path, ssl_key).await {
                    tracing::error!("failed to write key {}: {}", key_path, e);
                    return ApiResponse::error("Failed to save certificate key")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok();
                }
            }

            // SSL nginx config with HTTP redirect
            let ssl_nginx_config = format!(
                r#"server {{
    listen 80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_session_cache shared:SSL:10m;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";
    ssl_prefer_server_ciphers on;

    location / {{
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_pass http://{ip}:{port};
    }}

    location /.well-known/acme-challenge/ {{
        proxy_set_header Host $host;
        proxy_pass http://127.0.0.1:81$request_uri;
    }}
}}"#,
                domain = data.domain,
                ip = data.ip,
                port = data.port,
                cert_path = cert_path,
                key_path = key_path
            );

            // Update nginx config with SSL version
            if let Err(e) = fs::write(&sites_available, &ssl_nginx_config).await {
                tracing::error!(
                    "failed to write SSL nginx config {}_{}.conf: {}",
                    data.domain, data.port, e
                );
                return ApiResponse::error("Failed to write SSL nginx config")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            // Reload nginx again with SSL config
            let _ = Command::new("systemctl")
                .args(["reload", "nginx"])
                .output()
                .await;
        }

        ApiResponse::new_serialized(Response {})
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

mod delete {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use axum::Json;
    use serde::{Deserialize, Serialize};
    use tokio::fs;
    use tokio::process::Command;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize)]
    pub struct DeleteProxyRequest {
        domain: String,
        port: String,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {}

    #[utoipa::path(post, path = "/delete", responses(
        (status = ACCEPTED, body = inline(Response)),
        (status = BAD_REQUEST, body = ApiError),
    ), params(
        (
            "server" = uuid::Uuid,
            description = "The server uuid",
            example = "123e4567-e89b-12d3-a456-426614174000",
        ),
    ))]
    pub async fn route(
        _server: GetServer,
        Json(data): Json<DeleteProxyRequest>,
    ) -> ApiResponseResult {
        let sites_available = format!("/etc/nginx/sites-available/{}_{}.conf", data.domain, data.port);
        let sites_enabled = format!("/etc/nginx/sites-enabled/{}_{}.conf", data.domain, data.port);

        // Remove sites-available config
        if let Err(e) = fs::remove_file(&sites_available).await {
            tracing::error!(
                "failed to remove nginx config sites-available/{}_{}.conf: {}",
                data.domain, data.port, e
            );
        }

        // Remove sites-enabled symlink
        if let Err(e) = fs::remove_file(&sites_enabled).await {
            tracing::error!(
                "failed to remove nginx config sites-enabled/{}_{}.conf: {}",
                data.domain, data.port, e
            );
        }

        // Reload nginx
        let _ = Command::new("systemctl")
            .args(["reload", "nginx"])
            .output()
            .await;

        ApiResponse::new_serialized(Response {})
            .with_status(StatusCode::ACCEPTED)
            .ok()
    }
}

pub fn router(state: &State) -> OpenApiRouter<State> {
    OpenApiRouter::new()
        .routes(routes!(create::route))
        .routes(routes!(delete::route))
        .with_state(state.clone())
}
