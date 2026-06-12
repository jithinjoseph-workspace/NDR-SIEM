use crate::correlator::CorrelationHit;
use crate::scoring::RiskResult;
use crate::enrichment::EnrichmentData;

pub fn evaluate_condition(
    cond_field: &str,
    cond_op: &str,
    cond_value: &str,
    hit: &CorrelationHit,
    risk: &RiskResult,
    enrichment: &EnrichmentData,
) -> bool {
    match cond_field {
        "score" => {
            let score_val = cond_value.parse::<f32>().unwrap_or(0.0);
            match cond_op {
                ">" => risk.score > score_val,
                ">=" => risk.score >= score_val,
                "<" => risk.score < score_val,
                "<=" => risk.score <= score_val,
                "==" => (risk.score - score_val).abs() < f32::EPSILON,
                _ => false,
            }
        }
        "severity" => {
            match cond_op {
                "==" => risk.severity.as_str().eq_ignore_ascii_case(cond_value),
                "contains" => risk.severity.as_str().to_lowercase().contains(&cond_value.to_lowercase()),
                _ => false,
            }
        }
        "threat_intel" => {
            let val = cond_value.to_lowercase() == "true" || cond_value == "1";
            match cond_op {
                "==" => enrichment.is_malicious == val,
                _ => false,
            }
        }
        "src_country" => {
            let country = enrichment.src_geo.as_ref()
                .map(|g| g.country_code.clone())
                .unwrap_or_default();
            match cond_op {
                "==" => country.eq_ignore_ascii_case(cond_value),
                "contains" => country.to_lowercase().contains(&cond_value.to_lowercase()),
                _ => false,
            }
        }
        "sigma_tag" => {
            // Check if any tag matches
            match cond_op {
                "==" => risk.tags.iter().any(|t| t.eq_ignore_ascii_case(cond_value)),
                "contains" => risk.tags.iter().any(|t| t.to_lowercase().contains(&cond_value.to_lowercase())),
                _ => false,
            }
        }
        _ => false,
    }
}
