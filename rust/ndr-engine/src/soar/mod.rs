use serde::{Serialize, Deserialize};

pub mod actions;
pub mod conditions;
pub mod firewall;
pub mod switch;

#[derive(Debug, Serialize, Deserialize)]
pub struct SoarNativePlaybook {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: u8,
    pub cond_field: String,
    pub cond_op: String,
    pub cond_value: String,
    pub action_type: String,
    pub action_config: String,
    pub run_count: u64,
    pub last_run: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    pub tenant_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoarPlaybookRun {
    pub id: String,
    pub playbook_id: String,
    pub playbook_name: String,
    pub hit_id: String,
    pub status: String,
    pub detail: String,
    pub created_at: String,
    pub tenant_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
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

use crate::api::AppState;
use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;

pub async fn execute_native_playbooks(
    state: &AppState,
    hit: CorrelationHit,
    risk: RiskResult,
    enrichment: EnrichmentData,
    tenant_id: &str,
) {
    let playbooks = match state.ch_storage.get_native_playbooks(tenant_id).await {
        Ok(p) => p,
        Err(_) => return,
    };

    for pb in playbooks {
        if pb.enabled != 1 { continue; }
        
        let triggered = conditions::evaluate_condition(
            &pb.cond_field,
            &pb.cond_op,
            &pb.cond_value,
            &hit,
            &risk,
            &enrichment,
        );

        if triggered {
            actions::execute_action(state, &pb, &hit, &risk, &enrichment).await;
        }
    }
}
