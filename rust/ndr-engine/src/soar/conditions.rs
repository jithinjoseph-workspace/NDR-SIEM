use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;
use provigil_common::soar::{SoarContext, SoarNativePlaybook};

/// Build a generic SoarContext from ndr-engine-specific types, then delegate
/// to the shared pure evaluator in provigil_common.
pub fn evaluate_condition(
    cond_field: &str,
    cond_op: &str,
    cond_value: &str,
    hit: &CorrelationHit,
    risk: &RiskResult,
    enrichment: &EnrichmentData,
) -> bool {
    let src_ip = match hit.source.as_str() {
        "agent-s" => hit.agent_s.source_ip.clone().unwrap_or_default(),
        _ => hit.agent_z.source_ip.clone()
            .or_else(|| hit.agent_s.source_ip.clone())
            .unwrap_or_default(),
    };
    let dst_ip = match hit.source.as_str() {
        "agent-s" => hit.agent_s.dest_ip.clone().unwrap_or_default(),
        _ => hit.agent_z.dest_ip.clone()
            .or_else(|| hit.agent_s.dest_ip.clone())
            .unwrap_or_default(),
    };
    let src_country = enrichment.src_geo.as_ref()
        .map(|g| g.country_code.clone())
        .unwrap_or_default();

    let ctx = SoarContext {
        score:        risk.score,
        severity:     risk.severity.as_str().to_string(),
        is_malicious: enrichment.is_malicious,
        src_country,
        tags:         risk.tags.clone(),
        src_ip,
        dst_ip,
        community_id: hit.community_id.clone(),
        tenant_id:    String::new(), // filled by caller when needed
    };

    // Delegate to the shared pure evaluator
    let pb = SoarNativePlaybook {
        id: String::new(), name: String::new(), description: String::new(),
        enabled: 1,
        cond_field: cond_field.to_string(),
        cond_op:    cond_op.to_string(),
        cond_value: cond_value.to_string(),
        action_type: String::new(), action_config: String::new(),
        run_count: 0, last_run: None,
        created_at: String::new(), updated_at: String::new(),
        tenant_id:  String::new(),
    };
    provigil_common::soar::conditions::evaluate_condition(&pb, &ctx)
}
