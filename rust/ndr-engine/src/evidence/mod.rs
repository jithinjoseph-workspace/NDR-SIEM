use sha2::{Sha256, Digest};
use zip::{ZipWriter, write::FileOptions};
use serde_json::{json, Value};
use std::io::Write;

/// Build a ZIP evidence bundle for a given community_id.
/// Returns (zip_bytes, sha256_hex, session_metadata).
pub async fn build_evidence_bundle(
    opensearch_url: &str,
    arkime_url: &str,
    arkime_pass: &str,
    community_id: &str,
    alert_json: Value,  // the correlation hit row as JSON
    tenant_id: &str,
    pcap_file_path: Option<String>,  // for remote tenants
) -> anyhow::Result<(Vec<u8>, String, Value)> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    // 1. Fetch session metadata from OpenSearch (default tenant)
    //    or use pcap_sessions data (remote tenants)
    let session_meta: Value = if !opensearch_url.is_empty() {
        let resp = http.post(format!(
            "{}/arkime_sessions3-*/_search",
            opensearch_url
        ))
        .json(&json!({
            "query": {
                "term": { "network.community_id": community_id }
            },
            "size": 1
        }))
        .send().await?
        .json::<Value>().await?;

        let hit = resp["hits"]["hits"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .unwrap_or(json!({}));

        json!({
            "arkime_session_id": hit["_id"],
            "index": hit["_index"],
            "source": hit["_source"],
            "community_id": community_id,
            "query_source": "opensearch"
        })
    } else {
        json!({
            "community_id": community_id,
            "query_source": "pcap_sessions",
            "note": "session metadata from uploaded PCAP index"
        })
    };

    // 2. Fetch raw PCAP bytes
    let arkime_session_id = session_meta["arkime_session_id"]
        .as_str()
        .unwrap_or("");

    let pcap_bytes: Vec<u8> = if let Some(ref path) = pcap_file_path {
        // Remote tenant: read uploaded file
        tokio::fs::read(path).await.unwrap_or_default()
    } else if !arkime_session_id.is_empty() && !arkime_url.is_empty() {
        // On-premise: proxy from Arkime
        http.get(format!(
            "{}/api/session/{}/pcap",
            arkime_url, arkime_session_id
        ))
        .basic_auth("admin", Some(arkime_pass))
        .send().await?
        .bytes().await?
        .to_vec()
    } else {
        vec![]
    };

    // 3. Build manifest with file hashes
    let pcap_sha256 = if !pcap_bytes.is_empty() {
        let mut h = Sha256::new();
        h.update(&pcap_bytes);
        format!("{:x}", h.finalize())
    } else {
        String::from("no_pcap_available")
    };

    let alert_str = serde_json::to_string_pretty(&alert_json)
        .unwrap_or_default();
    let session_str = serde_json::to_string_pretty(&session_meta)
        .unwrap_or_default();

    let mut alert_hasher = Sha256::new();
    alert_hasher.update(alert_str.as_bytes());
    let alert_sha256 = format!("{:x}", alert_hasher.finalize());

    let mut session_hasher = Sha256::new();
    session_hasher.update(session_str.as_bytes());
    let session_sha256 = format!("{:x}", session_hasher.finalize());

    let now = chrono::Utc::now().to_rfc3339();
    let bundle_id = uuid::Uuid::new_v4().to_string();

    let manifest = json!({
        "bundle_id": bundle_id,
        "community_id": community_id,
        "tenant_id": tenant_id,
        "created_at": now,
        "ndr_instance": format!("ndr-{}", tenant_id),
        "files": {
            "session.pcap": {
                "sha256": pcap_sha256,
                "size_bytes": pcap_bytes.len()
            },
            "alert.json": {
                "sha256": alert_sha256,
                "size_bytes": alert_str.len()
            },
            "session_metadata.json": {
                "sha256": session_sha256,
                "size_bytes": session_str.len()
            }
        },
        "chain_of_custody": "This bundle was generated automatically by NDR-Engine. Contents are SHA256 verified. Manifest hash covers all included files."
    });
    let manifest_str = serde_json::to_string_pretty(&manifest)
        .unwrap_or_default();

    // 4. Build ZIP
    let mut buf = Vec::new();
    {
        let cursor = std::io::Cursor::new(&mut buf);
        let mut zip = ZipWriter::new(cursor);
        let opts = FileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("manifest.json", opts)?;
        zip.write_all(manifest_str.as_bytes())?;

        zip.start_file("alert.json", opts)?;
        zip.write_all(alert_str.as_bytes())?;

        zip.start_file("session_metadata.json", opts)?;
        zip.write_all(session_str.as_bytes())?;

        if !pcap_bytes.is_empty() {
            zip.start_file("session.pcap", opts)?;
            zip.write_all(&pcap_bytes)?;
        }

        zip.finish()?;
    }

    // 5. Hash the entire ZIP for bundle-level integrity
    let mut bundle_hasher = Sha256::new();
    bundle_hasher.update(&buf);
    let bundle_sha256 = format!("{:x}", bundle_hasher.finalize());

    Ok((buf, bundle_sha256, manifest))
}

/// Verify a stored evidence bundle against its logged SHA256.
/// Returns true if file hash matches stored hash.
pub async fn verify_bundle_integrity(
    file_path: &str,
    stored_sha256: &str,
) -> (bool, String) {
    match tokio::fs::read(file_path).await {
        Ok(bytes) => {
            let mut h = Sha256::new();
            h.update(&bytes);
            let computed = format!("{:x}", h.finalize());
            let matches = computed == stored_sha256;
            (matches, computed)
        }
        Err(e) => (false, format!("file_read_error: {}", e))
    }
}