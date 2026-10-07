pub mod actions;
pub mod conditions;
pub mod firewall;
pub mod switch;

use serde::{Deserialize, Serialize};

// ── Playbook definition ───────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarNativePlaybook {
    pub id:            String,
    pub name:          String,
    pub description:   String,
    pub enabled:       u8,
    pub cond_field:    String,
    pub cond_op:       String,
    pub cond_value:    String,
    pub action_type:   String,
    pub action_config: String,
    pub run_count:     u64,
    pub last_run:      Option<String>,
    pub created_at:    String,
    pub updated_at:    String,
    pub tenant_id:     String,
}

// ── Playbook run log ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoarPlaybookRun {
    pub id:            String,
    pub playbook_id:   String,
    pub playbook_name: String,
    pub hit_id:        String,
    pub status:        String,
    pub detail:        String,
    pub created_at:    String,
    pub tenant_id:     String,
}

// ── Active IP block ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveBlock {
    pub id:               String,
    pub src_ip:           String,
    pub src_port:         u16,
    pub dst_ip:           String,
    pub dst_port:         u16,
    pub community_id:     String,
    pub triggered_by:     String,
    pub sensor_id:        String,
    pub firewall_type:    String,
    pub firewall_rule_id: String,
    pub rst_injected:     u8,
    pub duration_hours:   u16,
    pub expires_at:       String,
    pub status:           String,
    pub reason:           String,
    pub tenant_id:        String,
    pub created_at:       String,
}

// ── Device isolation ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIsolation {
    pub id:                 String,
    pub tenant_id:          String,
    pub target_ip:          String,
    pub gateway_ip:         String,
    pub method:             String,
    pub enforcement:        String,
    pub enforcement_detail: String,
    pub triggered_by:       String,
    pub sensor_id:          String,
    pub reason:             String,
    pub status:             String,
    pub created_at:         String,
    pub updated_at:         String,
}

// ── Generic event context ─────────────────────────────────────────────────────
//
// Both ndr-engine and siem-engine fill this from their own event types before
// calling evaluate_condition().  No engine-specific imports required here.

#[derive(Debug, Clone, Default)]
pub struct SoarContext {
    /// 0.0 – 100.0 risk score
    pub score: f32,
    /// "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    pub severity: String,
    /// Whether the src/dst IP matched a threat-intel IOC
    pub is_malicious: bool,
    /// Two-letter ISO country code for source IP (empty if unknown)
    pub src_country: String,
    /// Classification tags on the alert (sigma tags, correlation tags, etc.)
    pub tags: Vec<String>,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    /// Unique flow identifier (community_id or similar)
    pub community_id: String,
    pub tenant_id: String,
}

/// Tags that say how an alert was seen (protocol, severity band, port), not what it is. They never
/// decide which case an alert belongs to.
const GENERIC_TAG_PREFIXES: &[&str] = &["protocol:", "alert-sev-", "t:", "port:"];
const GENERIC_TAGS: &[&str] = &["half-open", "no-response", "smb", "threat-intel"];

/// The tag an alert is grouped by: its first tag that says what the alert is. `None` when it has none.
pub fn grouping_tag(tags: &[String]) -> Option<String> {
    tags.iter()
        .map(|t| t.trim())
        .find(|t| !t.is_empty()
            && !GENERIC_TAGS.contains(t)
            && !GENERIC_TAG_PREFIXES.iter().any(|p| t.starts_with(p)))
        .map(|t| t.to_string())
}

/// How an alert may join an open case for its flow (the same two IP addresses, either direction).
#[derive(Debug, Clone, PartialEq)]
pub enum FlowGroup {
    /// The same kind of alert (its grouping tag), with an open case created in the last 7 days.
    SameKind(String),
    /// Any alert on the same flow, with an open case created in the last 10 minutes. Critical alerts
    /// use this: one flow is one incident, even when two signatures fire on it.
    SameFlow,
}

/// How an alert may join an open case, or `None` when it must open its own case. Critical alerts
/// group by flow. Other threat-intel alerts open their own case, and so do alerts with no kind tag.
pub fn group_for(severity: &str, is_malicious: bool, tags: &[String]) -> Option<FlowGroup> {
    if severity.eq_ignore_ascii_case("CRITICAL") {
        return Some(FlowGroup::SameFlow);
    }
    if is_malicious || tags.iter().any(|t| t == "threat-intel") {
        return None;
    }
    grouping_tag(tags).map(FlowGroup::SameKind)
}

#[cfg(test)]
mod grouping_tests {
    use super::*;

    fn tags(v: &[&str]) -> Vec<String> { v.iter().map(|s| s.to_string()).collect() }

    #[test]
    fn the_grouping_tag_is_what_the_alert_is_not_how_it_was_seen() {
        assert_eq!(grouping_tag(&tags(&["protocol:http", "alert-sev-high", "port-scan"])), Some("port-scan".into()));
        assert_eq!(grouping_tag(&tags(&["protocol:dns", "suricata:2404300"])), Some("suricata:2404300".into()));
        assert_eq!(grouping_tag(&tags(&["protocol:http", "half-open"])), None, "nothing says what it is");
    }

    #[test]
    fn a_critical_alert_groups_by_flow_whatever_its_signature() {
        assert_eq!(group_for("CRITICAL", false, &tags(&["suricata:2024364"])), Some(FlowGroup::SameFlow));
        assert_eq!(group_for("CRITICAL", false, &tags(&["ids-alert", "protocol:http"])), Some(FlowGroup::SameFlow));
        assert_eq!(group_for("CRITICAL", true, &tags(&["threat-intel"])), Some(FlowGroup::SameFlow));
    }

    #[test]
    fn other_threat_intel_alerts_open_their_own_case_and_the_rest_group_by_kind() {
        assert_eq!(group_for("HIGH", true, &tags(&["port-scan"])), None, "a threat-intel IOC match");
        assert_eq!(group_for("HIGH", false, &tags(&["threat-intel", "port-scan"])), None);
        assert_eq!(group_for("HIGH", false, &tags(&["port-scan"])), Some(FlowGroup::SameKind("port-scan".into())));
        assert_eq!(group_for("HIGH", false, &tags(&["protocol:http"])), None, "no kind tag to group by");
    }
}

// ── Storage abstraction for SOAR actions ─────────────────────────────────────
//
// Both ndr-engine and siem-engine implement this trait on their ChStorage type.
// execute_action() in provigil-common::soar::actions takes &dyn SoarStore.

#[async_trait::async_trait]
pub trait SoarStore: Send + Sync {
    async fn soar_get_integrations(&self, tenant_id: &str) -> Vec<serde_json::Value>;
    /// The open case this alert may join, for the given grouping. Matches the flow in either direction.
    async fn soar_find_open_case(&self, src: &str, dst: &str, group: &FlowGroup, tenant_id: &str) -> Option<(String, String, String, String)>;
    async fn soar_add_comment(&self, case_id: &str, author: &str, comment: &str, tenant_id: &str);
    async fn soar_escalate_case(&self, case_id: &str, severity: &str, priority: &str, tenant_id: &str);
    async fn soar_next_case_number(&self, tenant_id: &str) -> String;
    async fn soar_create_case(
        &self, id: &str, case_number: &str, title: &str, description: &str,
        severity: &str, priority: &str, status: &str, assigned_to: &str,
        src_ip: &str, dst_ip: &str, community_id: &str, tags: &[String], tenant_id: &str,
    ) -> anyhow::Result<()>;
    async fn soar_get_pcap_sessions(&self, tenant_id: &str, cid: &str, limit: usize) -> Vec<serde_json::Value>;
    /// Saves real evidence content as a proper evidence bundle — visible on the Evidence &
    /// Forensics page like any other bundle, not just text buried in a case comment or
    /// description. Storage keeps one bundle per community_id, so this is safe to call more
    /// than once for the same session. Returns the bundle id actually stored.
    async fn soar_save_evidence_bundle(
        &self, tenant_id: &str, community_id: &str, content: &[u8],
        src_ip: &str, dst_ip: &str, severity: &str,
    ) -> anyhow::Result<String>;
    async fn soar_get_events(&self, community_id: &str, tenant_id: &str) -> serde_json::Value;
    async fn soar_insert_block(&self, block: &ActiveBlock) -> anyhow::Result<()>;
    async fn soar_insert_run(&self, run: &SoarPlaybookRun) -> anyhow::Result<()>;
}
