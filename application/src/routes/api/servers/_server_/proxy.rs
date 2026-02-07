use super::State;
use utoipa_axum::{router::OpenApiRouter, routes};

mod create {
    use crate::{
        response::{ApiResponse, ApiResponseResult},
        routes::{ApiError, api::servers::_server_::GetServer},
    };
    use axum::http::StatusCode;
    use axum::Json;
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount,
        NewOrder, OrderStatus,
    };
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use std::time::Duration;
    use tokio::fs;
    use tokio::process::Command;
    use tokio::time::sleep;
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

    /// Obtain a Let's Encrypt certificate using HTTP-01 challenge
    async fn obtain_lets_encrypt_cert(
        domain: &str,
        email: &str,
        challenge_dir: &str,
    ) -> Result<(String, String), String> {
        // Create a new ACME account using the builder pattern
        let (account, _credentials) = Account::builder()
            .map_err(|e| format!("Failed to create account builder: {}", e))?
            .create(
                &NewAccount {
                    contact: &[&format!("mailto:{}", email)],
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                LetsEncrypt::Production.url().to_string(),
                None,
            )
            .await
            .map_err(|e| format!("Failed to create ACME account: {}", e))?;

        // Create identifiers for the order
        let identifiers = vec![Identifier::Dns(domain.to_string())];
        
        // Create a new order for the certificate
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("Failed to create order: {}", e))?;

        // Get authorizations
        let authorizations = order
            .authorizations()
            .await
            .map_err(|e| format!("Failed to get authorizations: {}", e))?;

        for authz in authorizations {
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => return Err("Authorization in unexpected state".to_string()),
            }

            // Find HTTP-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .ok_or("No HTTP-01 challenge found")?;

            // Create the challenge file
            let token = &challenge.token;
            let key_authorization = order.key_authorization(challenge);

            // Write challenge response to well-known path
            let challenge_path = format!("{}/.well-known/acme-challenge/{}", challenge_dir, token);

            // Ensure directory exists
            if let Some(parent) = Path::new(&challenge_path).parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("Failed to create challenge directory: {}", e))?;
            }

            fs::write(&challenge_path, key_authorization.as_str())
                .await
                .map_err(|e| format!("Failed to write challenge file: {}", e))?;

            // Set challenge as ready
            order
                .set_challenge_ready(&challenge.url)
                .await
                .map_err(|e| format!("Failed to set challenge ready: {}", e))?;

            // Poll for authorization to become valid
            for _ in 0..20 {
                sleep(Duration::from_secs(2)).await;
                let updated_authz = order
                    .authorizations()
                    .await
                    .map_err(|e| format!("Failed to refresh authorization: {}", e))?;

                if updated_authz
                    .iter()
                    .all(|a| matches!(a.status, AuthorizationStatus::Valid))
                {
                    break;
                }
            }

            // Clean up challenge file
            let _ = fs::remove_file(&challenge_path).await;
        }

        // Wait for order to be ready
        let mut attempts = 0;
        loop {
            let state = order.state();

            if let OrderStatus::Ready | OrderStatus::Invalid | OrderStatus::Valid = state.status {
                if state.status == OrderStatus::Invalid {
                    return Err("Order was rejected".to_string());
                }
                break;
            }

            attempts += 1;
            if attempts > 20 {
                return Err("Order did not become ready in time".to_string());
            }
            sleep(Duration::from_secs(2)).await;
            
            // Refresh the order state
            order.refresh().await.map_err(|e| format!("Failed to refresh order: {}", e))?;
        }

        // Generate a private key and CSR
        let key_pair =
            KeyPair::generate().map_err(|e| format!("Failed to generate key pair: {}", e))?;

        let mut params = CertificateParams::new(vec![domain.to_string()])
            .map_err(|e| format!("Failed to create cert params: {}", e))?;
        params.distinguished_name = DistinguishedName::new();

        let csr = params
            .serialize_request(&key_pair)
            .map_err(|e| format!("Failed to create CSR: {}", e))?;

        // Finalize the order with CSR
        order
            .finalize(csr.der())
            .await
            .map_err(|e| format!("Failed to finalize order: {}", e))?;

        // Wait for certificate
        let cert_chain = loop {
            let state = order.state();

            if let OrderStatus::Valid = state.status {
                break order
                    .certificate()
                    .await
                    .map_err(|e| format!("Failed to get certificate: {}", e))?
                    .ok_or("No certificate returned")?;
            }

            if let OrderStatus::Invalid = state.status {
                return Err("Order became invalid".to_string());
            }

            sleep(Duration::from_secs(2)).await;
            order.refresh().await.map_err(|e| format!("Failed to refresh order: {}", e))?;
        };

        Ok((cert_chain, key_pair.serialize_pem()))
    }

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
        let sites_available = format!(
            "/etc/nginx/sites-available/{}_{}.conf",
            data.domain, data.port
        );
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
        root /var/www/acme-challenge;
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
                data.domain,
                data.port,
                e
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
                tracing::error!("failed to create cert directory {}: {}", cert_dir, e);
                return ApiResponse::error("Failed to create certificate directory")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            let (cert_pem, key_pem) = if data.use_lets_encrypt {
                // Use Let's Encrypt
                let email = data.client_email.as_deref().unwrap_or("admin@example.com");
                let challenge_dir = "/var/www/acme-challenge";

                // Ensure challenge directory exists
                if let Err(e) = fs::create_dir_all(challenge_dir).await {
                    tracing::error!("failed to create ACME challenge directory: {}", e);
                    return ApiResponse::error("Failed to create ACME challenge directory")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok();
                }

                match obtain_lets_encrypt_cert(&data.domain, email, challenge_dir).await {
                    Ok((cert, key)) => (cert, key),
                    Err(e) => {
                        tracing::error!("Let's Encrypt certificate request failed: {}", e);
                        return ApiResponse::error(&format!(
                            "Let's Encrypt certificate request failed: {}",
                            e
                        ))
                        .with_status(StatusCode::BAD_REQUEST)
                        .ok();
                    }
                }
            } else {
                // Custom SSL certificates
                let ssl_cert = match &data.ssl_cert {
                    Some(cert) => cert.clone(),
                    None => {
                        return ApiResponse::error("SSL certificate required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                let ssl_key = match &data.ssl_key {
                    Some(key) => key.clone(),
                    None => {
                        return ApiResponse::error("SSL key required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                (ssl_cert, ssl_key)
            };

            // Write certificate files
            if let Err(e) = fs::write(&cert_path, &cert_pem).await {
                tracing::error!("failed to write cert {}: {}", cert_path, e);
                return ApiResponse::error("Failed to save certificate")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            if let Err(e) = fs::write(&key_path, &key_pem).await {
                tracing::error!("failed to write key {}: {}", key_path, e);
                return ApiResponse::error("Failed to save certificate key")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
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
        root /var/www/acme-challenge;
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
                    data.domain,
                    data.port,
                    e
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
        let sites_available = format!(
            "/etc/nginx/sites-available/{}_{}.conf",
            data.domain, data.port
        );
        let sites_enabled = format!("/etc/nginx/sites-enabled/{}_{}.conf", data.domain, data.port);

        // Remove sites-available config
        if let Err(e) = fs::remove_file(&sites_available).await {
            tracing::error!(
                "failed to remove nginx config sites-available/{}_{}.conf: {}",
                data.domain,
                data.port,
                e
            );
        }

        // Remove sites-enabled symlink
        if let Err(e) = fs::remove_file(&sites_enabled).await {
            tracing::error!(
                "failed to remove nginx config sites-enabled/{}_{}.conf: {}",
                data.domain,
                data.port,
                e
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
