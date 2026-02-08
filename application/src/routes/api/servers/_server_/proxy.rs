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
        NewOrder, RetryPolicy,
    };
    use serde::{Deserialize, Serialize};
    use std::path::Path;
    use std::time::Duration;
    use tokio::fs;
    use utoipa::ToSchema;

    #[derive(ToSchema, Deserialize, Default, Clone, Copy, PartialEq)]
    #[serde(rename_all = "lowercase")]
    pub enum WebServer {
        #[default]
        Nginx,
        Apache,
    }

    #[derive(ToSchema, Deserialize)]
    pub struct CreateProxyRequest {
        domain: String,
        ip: String,
        port: String,
        #[serde(default)]
        webserver: WebServer,
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
    struct Response {
        config_path: String,
        message: String,
    }

    fn generate_nginx_config(domain: &str, ip: &str, port: &str, ssl: bool, cert_path: Option<&str>, key_path: Option<&str>) -> String {
        if ssl {
            let cert = cert_path.unwrap_or("");
            let key = key_path.unwrap_or("");
            format!(
                r#"server {{
    listen 80;
    server_name {domain};
    return 301 https://$server_name$request_uri;
}}

server {{
    listen 443 ssl http2;
    server_name {domain};

    ssl_certificate {cert};
    ssl_certificate_key {key};
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
}}"#
            )
        } else {
            format!(
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
}}"#
            )
        }
    }

    fn generate_apache_config(domain: &str, ip: &str, port: &str, ssl: bool, cert_path: Option<&str>, key_path: Option<&str>) -> String {
        if ssl {
            let cert = cert_path.unwrap_or("");
            let key = key_path.unwrap_or("");
            format!(
                r#"<VirtualHost *:80>
    ServerName {domain}
    Redirect permanent / https://{domain}/
</VirtualHost>

<VirtualHost *:443>
    ServerName {domain}

    SSLEngine on
    SSLCertificateFile {cert}
    SSLCertificateKeyFile {key}
    SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1

    ProxyPreserveHost On
    ProxyPass / http://{ip}:{port}/
    ProxyPassReverse / http://{ip}:{port}/

    <Location /.well-known/acme-challenge/>
        ProxyPass !
        Alias /var/www/acme-challenge/.well-known/acme-challenge/
    </Location>
</VirtualHost>"#
            )
        } else {
            format!(
                r#"<VirtualHost *:80>
    ServerName {domain}

    ProxyPreserveHost On
    ProxyPass /.well-known/acme-challenge/ !
    Alias /.well-known/acme-challenge/ /var/www/acme-challenge/.well-known/acme-challenge/
    ProxyPass / http://{ip}:{port}/
    ProxyPassReverse / http://{ip}:{port}/
</VirtualHost>"#
            )
        }
    }

    fn get_config_path(webserver: WebServer, domain: &str, port: &str) -> String {
        match webserver {
            WebServer::Nginx => format!("/etc/nginx/sites-available/{}_{}.conf", domain, port),
            WebServer::Apache => format!("/etc/apache2/sites-available/{}_{}.conf", domain, port),
        }
    }

    async fn obtain_lets_encrypt_cert(
        domain: &str,
        email: &str,
        challenge_dir: &str,
    ) -> Result<(String, String), String> {
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

        let identifiers = vec![Identifier::Dns(domain.to_string())];

        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("Failed to create order: {}", e))?;

        let mut authorizations = order.authorizations();
        while let Some(authz_result) = authorizations.next().await {
            let mut authz = authz_result
                .map_err(|e| format!("Failed to get authorization: {}", e))?;

            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => return Err("Authorization in unexpected state".to_string()),
            }

            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("No HTTP-01 challenge found")?;

            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization();

            let challenge_path = format!(
                "{}/.well-known/acme-challenge/{}",
                challenge_dir, token
            );

            if let Some(parent) = Path::new(&challenge_path).parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| format!("Failed to create challenge directory: {}", e))?;
            }

            fs::write(&challenge_path, key_authorization.as_str())
                .await
                .map_err(|e| format!("Failed to write challenge file: {}", e))?;

            challenge
                .set_ready()
                .await
                .map_err(|e| format!("Failed to set challenge ready: {}", e))?;

            let cleanup_path = challenge_path.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                let _ = fs::remove_file(&cleanup_path).await;
            });
        }
        drop(authorizations);

        let retry_policy = RetryPolicy::default();
        order
            .poll_ready(&retry_policy)
            .await
            .map_err(|e| format!("Order did not become ready: {}", e))?;

        let private_key_pem = order
            .finalize()
            .await
            .map_err(|e| format!("Failed to finalize order: {}", e))?;

        let cert_chain = order
            .poll_certificate(&retry_policy)
            .await
            .map_err(|e| format!("Failed to get certificate: {}", e))?;

        Ok((cert_chain, private_key_pem))
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
        let webserver = data.webserver;
        let config_path = get_config_path(webserver, &data.domain, &data.port);

        // Check if config already exists to prevent accidental overwrites
        if Path::new(&config_path).exists() {
            return ApiResponse::error(&format!(
                "Config already exists at {}. Delete it first before creating a new one.",
                config_path
            ))
            .with_status(StatusCode::CONFLICT)
            .ok();
        }

        let (cert_path, key_path) = if data.ssl {
            let cert_dir = format!("/srv/server_certs/{}", data.domain);
            let cert = format!("{}/cert.pem", cert_dir);
            let key = format!("{}/key.pem", cert_dir);

            if let Err(e) = fs::create_dir_all(&cert_dir).await {
                tracing::error!("failed to create cert directory {}: {}", cert_dir, e);
                return ApiResponse::error("Failed to create certificate directory")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            let (cert_pem, key_pem) = if data.use_lets_encrypt {
                let email = match &data.client_email {
                    Some(e) if !e.is_empty() && e.contains('@') => e.as_str(),
                    _ => {
                        return ApiResponse::error("A valid email address is required for Let's Encrypt certificates")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };
                let challenge_dir = "/var/www/acme-challenge";

                if let Err(e) = fs::create_dir_all(challenge_dir).await {
                    tracing::error!("failed to create ACME challenge directory: {}", e);
                    return ApiResponse::error("Failed to create ACME challenge directory")
                        .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                        .ok();
                }

                match obtain_lets_encrypt_cert(&data.domain, email, challenge_dir).await {
                    Ok((c, k)) => (c, k),
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
                let ssl_cert = match &data.ssl_cert {
                    Some(c) => c.clone(),
                    None => {
                        return ApiResponse::error("SSL certificate required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                let ssl_key = match &data.ssl_key {
                    Some(k) => k.clone(),
                    None => {
                        return ApiResponse::error("SSL key required when ssl=true")
                            .with_status(StatusCode::BAD_REQUEST)
                            .ok();
                    }
                };

                (ssl_cert, ssl_key)
            };

            if let Err(e) = fs::write(&cert, &cert_pem).await {
                tracing::error!("failed to write cert {}: {}", cert, e);
                return ApiResponse::error("Failed to save certificate")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            if let Err(e) = fs::write(&key, &key_pem).await {
                tracing::error!("failed to write key {}: {}", key, e);
                return ApiResponse::error("Failed to save certificate key")
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .ok();
            }

            (Some(cert), Some(key))
        } else {
            (None, None)
        };

        let config = match webserver {
            WebServer::Nginx => generate_nginx_config(
                &data.domain,
                &data.ip,
                &data.port,
                data.ssl,
                cert_path.as_deref(),
                key_path.as_deref(),
            ),
            WebServer::Apache => generate_apache_config(
                &data.domain,
                &data.ip,
                &data.port,
                data.ssl,
                cert_path.as_deref(),
                key_path.as_deref(),
            ),
        };

        if let Err(e) = fs::write(&config_path, &config).await {
            tracing::error!("failed to write config {}: {}", config_path, e);
            return ApiResponse::error("Failed to write webserver config")
                .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                .ok();
        }

        let webserver_name = match webserver {
            WebServer::Nginx => "nginx",
            WebServer::Apache => "apache2",
        };

        ApiResponse::new_serialized(Response {
            config_path: config_path.clone(),
            message: format!(
                "Config written. Enable site and reload {} to apply.",
                webserver_name
            ),
        })
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
    use utoipa::ToSchema;

    use super::create::WebServer;

    #[derive(ToSchema, Deserialize)]
    pub struct DeleteProxyRequest {
        domain: String,
        port: String,
        #[serde(default)]
        webserver: WebServer,
    }

    #[derive(ToSchema, Serialize)]
    struct Response {
        message: String,
    }

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
        let webserver = data.webserver;

        let (sites_available, sites_enabled) = match webserver {
            WebServer::Nginx => (
                format!("/etc/nginx/sites-available/{}_{}.conf", data.domain, data.port),
                format!("/etc/nginx/sites-enabled/{}_{}.conf", data.domain, data.port),
            ),
            WebServer::Apache => (
                format!("/etc/apache2/sites-available/{}_{}.conf", data.domain, data.port),
                format!("/etc/apache2/sites-enabled/{}_{}.conf", data.domain, data.port),
            ),
        };

        if let Err(e) = fs::remove_file(&sites_available).await {
            tracing::warn!("failed to remove config {}: {}", sites_available, e);
        }

        if let Err(e) = fs::remove_file(&sites_enabled).await {
            tracing::warn!("failed to remove symlink {}: {}", sites_enabled, e);
        }

        let webserver_name = match webserver {
            WebServer::Nginx => "nginx",
            WebServer::Apache => "apache2",
        };

        ApiResponse::new_serialized(Response {
            message: format!("Config removed. Reload {} to apply.", webserver_name),
        })
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
