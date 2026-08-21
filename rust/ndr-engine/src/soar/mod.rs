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
    SoarStore,
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

    // Build context once — shared by both condition evaluation and action execution.
    let ctx = conditions::build_soar_context(&hit, &risk, &enrichment, tenant_id);

    for pb in playbooks {
        if pb.enabled != 1 { continue; }

        let triggered = provigil_common::soar::conditions::evaluate_condition(&pb, &ctx);
        if triggered {
            provigil_common::soar::actions::execute_action(
                state.ch_storage.as_ref(),
                &pb,
                &ctx,
            ).await;
        }
    }
}
