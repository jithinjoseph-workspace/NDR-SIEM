pub mod actions;
pub mod conditions;
pub mod firewall;
pub mod switch;

// Re-export shared types from provigil-common — no duplication.
pub use provigil_common::soar::{
    SoarNativePlaybook,
    SoarPlaybookRun,
    ActiveBlock,
    DeviceIsolation,
    SoarContext,
};

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
