// Runs siem_init.sql against ClickHouse on startup — idempotent (IF NOT EXISTS everywhere)
// Only creates siem-specific tables; NDR tables are handled by ndr-engine's init.sql

use tracing::{info, warn, error};

const SIEM_INIT_SQL: &str = include_str!("../siem_init.sql");

/// Execute the SIEM schema init for a given tenant database.
/// db = "ndr" for default tenant, "ndr_{tenant_id}" for others.
pub async fn run(clickhouse_url: &str, db: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    // Step 1: create the DB on the local node first (no ON CLUSTER — always succeeds)
    let create_db = format!("CREATE DATABASE IF NOT EXISTS {db}");
    let r = client.post(clickhouse_url).body(create_db).send().await?;
    if !r.status().is_success() {
        let body = r.text().await.unwrap_or_default();
        error!("SIEM DB create failed for {db}: {body}");
    }

    // Step 2: propagate the DB to all cluster nodes so ON CLUSTER table DDL succeeds
    let propagate = format!("CREATE DATABASE IF NOT EXISTS {db} ON CLUSTER ndr_cluster");
    let r2 = client.post(clickhouse_url).body(propagate).send().await?;
    if !r2.status().is_success() {
        // Non-fatal — may fail if cluster not configured or DB already exists everywhere
        let body = r2.text().await.unwrap_or_default();
        warn!("SIEM DB cluster propagation for {db} (non-fatal): {body}");
    }

    // Step 3: create all tables (split SQL on ';', skip blank/comment-only chunks)
    let sql = SIEM_INIT_SQL.replace("__DB__", db);
    for stmt in sql.split(';') {
        let stmt = stmt.trim();
        // Skip if every non-empty line is a comment
        let has_real_content = stmt.lines().any(|l| {
            let t = l.trim();
            !t.is_empty() && !t.starts_with("--")
        });
        if !has_real_content {
            continue;
        }
        // Skip the embedded CREATE DATABASE — handled above
        if stmt.trim_start_matches(|c: char| c.is_whitespace() || c == '-')
               .to_ascii_uppercase()
               .starts_with("CREATE DATABASE") {
            continue;
        }

        let resp = client
            .post(clickhouse_url)
            .body(stmt.to_string())
            .send()
            .await?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            error!("SIEM init stmt failed on {db}: {body}");
            error!("Statement was: {}", &stmt[..stmt.len().min(120)]);
        }
    }

    info!("SIEM schema init complete for db={db}");
    Ok(())
}
