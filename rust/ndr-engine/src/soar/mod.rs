use serde::{Serialize, Deserialize};

pub mod actions;
pub mod conditions;

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

use crate::api::AppState;
use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;

pub async fn execute_native_playbooks(
    state: &AppState,
    hit: CorrelationHit,
    risk: RiskResult,
    enrichment: EnrichmentData,
) {
    let playbooks = match state.ch_storage.get_native_playbooks().await {
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
