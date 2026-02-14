use anyhow::Context;
use compact_str::ToCompactString;
use hmac::digest::KeyInit;
use jwt::VerifyWithKey;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

#[derive(Deserialize, Serialize)]
pub struct BasePayload {
    #[serde(rename = "iss")]
    pub issuer: compact_str::CompactString,
    #[serde(rename = "sub")]
    pub subject: Option<compact_str::CompactString>,
    #[serde(rename = "aud")]
    pub audience: Vec<compact_str::CompactString>,
    #[serde(rename = "exp")]
    pub expiration_time: Option<i64>,
    #[serde(rename = "nbf")]
    pub not_before: Option<i64>,
    #[serde(rename = "iat")]
    pub issued_at: Option<i64>,
    #[serde(rename = "jti")]
    pub jwt_id: compact_str::CompactString,
}

impl BasePayload {
    pub async fn validate(&self, client: &JwtClient) -> bool {
        let now = chrono::Utc::now().timestamp();

        if let Some(exp) = self.expiration_time {
            if exp < now {
                return false;
            }
        } else {
            return false;
        }

        if let Some(nbf) = self.not_before
            && nbf > now
        {
            return false;
        }

        if let Some(iat) = self.issued_at {
            if iat > now || iat < client.boot_time.timestamp() {
                return false;
            }
        } else {
            return false;
        }

        if let Some(expired_until) = client.denied_jtokens.read().await.get(&self.jwt_id)
            && let Some(issued) = self.issued_at
            && issued < expired_until.timestamp()
        {
            return false;
        }

        true
    }
}

type CountingMap = HashMap<compact_str::CompactString, (usize, chrono::DateTime<chrono::Utc>)>;

pub struct JwtClient {
    pub key: hmac::Hmac<sha2::Sha256>,
    pub boot_time: chrono::DateTime<chrono::Utc>,
    pub max_jwt_uses: usize,

    pub denied_jtokens:
        Arc<RwLock<HashMap<compact_str::CompactString, chrono::DateTime<chrono::Utc>>>>,
    pub seen_jtoken_ids: Arc<RwLock<CountingMap>>,
}

impl JwtClient {
    pub fn new(config: &crate::config::InnerConfig) -> Self {
        let denied_jtokens = Arc::new(RwLock::new(HashMap::new()));
        let seen_jtoken_ids = Arc::new(RwLock::new(HashMap::new()));

        tokio::spawn({
            let denied_jtokens = Arc::clone(&denied_jtokens);
            let seen_jtoken_ids = Arc::clone(&seen_jtoken_ids);

            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;

                    let mut denied = denied_jtokens.write().await;
                    denied.retain(|_, &mut expiration| {
                        expiration > chrono::Utc::now() - chrono::Duration::hours(1)
                    });
                    drop(denied);

                    let mut seen = seen_jtoken_ids.write().await;
                    seen.retain(|_, &mut (_, expiration)| {
                        expiration > chrono::Utc::now() - chrono::Duration::hours(1)
                    });
                    drop(seen);
                }
            }
        });

        crate::spawn_handled(async move {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;

            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
            let socket = sntpc_net_tokio::UdpSocketWrapper::from(socket);
            let context = sntpc::NtpContext::new(sntpc::StdTimestampGen::default());

            let pool_ntp_addrs = tokio::net::lookup_host(("pool.ntp.org", 123))
                .await
                .context("failed to resolve pool.ntp.org")?;

            let get_pool_time = async |addr: std::net::SocketAddr| {
                tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    sntpc::get_time(addr, &socket, context),
                )
                .await?
                .map_err(|err| std::io::Error::other(format!("{:?}", err)))
                .context("failed to get time from pool.ntp.org")
            };

            for pool_ntp_addr in pool_ntp_addrs {
                let pool_time = match get_pool_time(pool_ntp_addr).await {
                    Ok(time) => time,
                    Err(err) => {
                        tracing::warn!("failed to get time from {:?}: {:?}", pool_ntp_addr, err);
                        continue;
                    }
                };

                let duration = std::time::Duration::from_micros(pool_time.offset().unsigned_abs());

                if duration > std::time::Duration::from_secs(5) {
                    if pool_time.offset().is_negative() {
                        tracing::warn!(
                            "system clock is behind by {:.2}s according to {:?}",
                            duration.as_secs_f64(),
                            pool_ntp_addr
                        );
                    } else {
                        tracing::warn!(
                            "system clock is ahead by {:.2}s according to {:?}",
                            duration.as_secs_f64(),
                            pool_ntp_addr
                        );
                    }
                } else if pool_time.offset().is_negative() {
                    tracing::info!(
                        "system clock is behind by {}ms according to {:?}",
                        duration.as_millis(),
                        pool_ntp_addr
                    );
                } else {
                    tracing::info!(
                        "system clock is ahead by {}ms according to {:?}",
                        duration.as_millis(),
                        pool_ntp_addr
                    );
                }
            }

            Ok::<_, anyhow::Error>(())
        });

        Self {
            key: hmac::Hmac::new_from_slice(config.token.as_bytes())
                .context("invalid token while constructing jwt client")
                .unwrap(),
            boot_time: chrono::Utc::now(),
            max_jwt_uses: config.api.max_jwt_uses,

            denied_jtokens,
            seen_jtoken_ids,
        }
    }

    #[inline]
    pub fn verify<T: DeserializeOwned>(&self, token: &str) -> Result<T, jwt::Error> {
        token.verify_with_key(&self.key)
    }

    pub async fn limited_jwt_id(&self, id: &str) -> bool {
        let seen = self.seen_jtoken_ids.read().await;
        if let Some((count, _)) = seen.get(id) {
            if *count >= self.max_jwt_uses {
                return false;
            } else {
                drop(seen);

                if self.max_jwt_uses != 0 {
                    let mut seen = self.seen_jtoken_ids.write().await;
                    if let Some((count, _)) = seen.get_mut(id) {
                        *count += 1;
                    }
                }
            }
        } else {
            drop(seen);

            self.seen_jtoken_ids
                .write()
                .await
                .insert(id.to_compact_string(), (1, chrono::Utc::now()));
        }

        true
    }

    pub async fn deny(&self, id: impl Into<compact_str::CompactString>) {
        let mut denied = self.denied_jtokens.write().await;
        denied.insert(id.into(), chrono::Utc::now());
    }
}
