use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LicenseClaims {
    pub tenant_id:   String,
    pub tenant_name: String,
    pub features:    Vec<String>,  // ["ndr", "ai", "soar"]
    pub max_sensors: u32,
    pub issued_by:   String,
    pub iat:         u64,
    pub exp:         u64,
}

impl LicenseClaims {
    pub fn has_feature(&self, f: &str) -> bool {
        self.features.iter().any(|x| x == f)
    }
}

pub fn generate_license(
    tenant_id:    &str,
    tenant_name:  &str,
    features:     Vec<String>,
    max_sensors:  u32,
    expires_days: u32,
    secret:       &str,
) -> anyhow::Result<String> {
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let claims = LicenseClaims {
        tenant_id:   tenant_id.to_string(),
        tenant_name: tenant_name.to_string(),
        features,
        max_sensors,
        issued_by:   "PromaSecure".to_string(),
        iat:         now,
        exp:         now + (expires_days as u64 * 86400),
    };
    Ok(encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))?)
}

pub fn verify_license(token: &str, secret: &str) -> anyhow::Result<LicenseClaims> {
    let mut v = Validation::new(Algorithm::HS256);
    v.validate_exp = true;
    Ok(decode::<LicenseClaims>(token, &DecodingKey::from_secret(secret.as_bytes()), &v)?.claims)
}
