//! "Ask your history": a question answered only from this tenant's own past investigations.
//!
//! The question is embedded and matched against the RAG index (`rag::search_similar`), the
//! closest past investigations are attached with how their cases ended (`incident_outcomes`),
//! and the AI is asked to answer from exactly those records. Its answer is checked before it is
//! shown: every session it cites must be one of the records it was given, otherwise the plain
//! list of records is shown instead. With no comparable records there is no AI call at all.

use serde::Serialize;

use crate::ai::provider::UseCase;
use crate::ai::rag::SimilarIncident;
use provigil_common::ai::{generate_with_providers, AiProvider};

pub const MAX_QUESTION_CHARS: usize = 300;
pub const MAX_RECORDS: usize = 5;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Source {
    pub community_id: String,
    pub verdict: String,
    pub reasoning: String,
    pub outcome: Option<String>,
    pub score: f32,
    pub src_ip: String,
    pub dst_ip: String,
    pub sensor_id: String,
    pub generated_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Answer {
    pub answer: String,
    /// "ai" when the AI's wording was used, "records" for the plain list.
    pub source: &'static str,
    /// Why the plain list was used: "no_records", "not_configured", "rejected", or "" for AI.
    pub reason: &'static str,
    pub sources: Vec<Source>,
}

pub fn sources_from(hits: &[SimilarIncident], outcomes: &std::collections::HashMap<String, (String, String)>) -> Vec<Source> {
    hits.iter().take(MAX_RECORDS).map(|h| Source {
        community_id: h.investigation.community_id.clone(),
        verdict: h.investigation.verdict.clone(),
        reasoning: h.investigation.reasoning.clone(),
        outcome: outcomes.get(&h.investigation.community_id).map(|o| o.0.clone()),
        score: h.score,
        src_ip: h.investigation.src_ip.clone(),
        dst_ip: h.investigation.dst_ip.clone(),
        sensor_id: h.investigation.sensor_id.clone(),
        generated_at: h.investigation.generated_at.clone(),
    }).collect()
}

pub const SYSTEM_PROMPT: &str = "You answer a SOC analyst's question using ONLY the past investigation records given. \
Never add facts, hosts, addresses or outcomes that are not in the records. Cite the community_id of each record \
you rely on, exactly as written. If the records do not answer the question, say so in one sentence. \
At most 90 words, plain text.";

pub fn user_prompt(question: &str, sources: &[Source]) -> String {
    let mut s = format!("QUESTION: {question}\n\nRECORDS:\n");
    for r in sources {
        let outcome = match r.outcome.as_deref() {
            Some("true_positive") => "closed as a confirmed attack",
            Some("false_positive") => "closed as a false positive",
            Some("closed_unknown") => "closed, no verdict recorded",
            _ => "no outcome recorded yet",
        };
        s.push_str(&format!(
            "- community_id {} | {} -> {} | sensor {} | AI verdict {} | {} | {}\n  reasoning: {}\n",
            r.community_id, r.src_ip, r.dst_ip, r.sensor_id, r.verdict, outcome, r.generated_at, r.reasoning
        ));
    }
    s.push_str("\nAnswer the question from these records only.");
    s
}

/// Every session id the answer cites must be one of the records. An answer citing anything else
/// is not grounded in what was retrieved, so it is not shown.
pub fn answer_is_grounded(answer: &str, sources: &[Source]) -> bool {
    let a = answer.trim();
    if a.is_empty() || a.chars().count() > 1200 { return false; }
    let re = regex::Regex::new(r"1:[A-Za-z0-9+/]{20,}={0,2}").unwrap();
    let cited: Vec<&str> = re.find_iter(a).map(|m| m.as_str()).collect();
    cited.iter().all(|c| sources.iter().any(|s| s.community_id == *c))
}

pub fn compose(question: &str, sources: Vec<Source>, ai_reply: &str, ai_state: &'static str) -> Answer {
    if sources.is_empty() {
        return Answer {
            answer: format!("No comparable past investigations found for \"{}\".", question.trim()),
            source: "records", reason: "no_records", sources,
        };
    }
    if ai_state.is_empty() && answer_is_grounded(ai_reply, &sources) {
        return Answer { answer: ai_reply.trim().to_string(), source: "ai", reason: "", sources };
    }
    let reason = if !ai_state.is_empty() { ai_state } else if ai_reply.trim().is_empty() { "no_ai_answer" } else { "rejected" };
    let answer = format!("{} comparable past investigation(s), listed below with how each ended.", sources.len());
    Answer { answer, source: "records", reason, sources }
}

/// Asks the providers (priority order) to answer from the records. Empty when none answers.
pub async fn ask(providers: &[AiProvider], question: &str, sources: &[Source]) -> String {
    generate_with_providers(providers, SYSTEM_PROMPT, &user_prompt(question, sources)).await
}

pub fn clean_question(q: &str) -> String {
    q.trim().chars().take(MAX_QUESTION_CHARS).collect()
}

pub async fn providers(ch: &clickhouse::Client) -> Vec<AiProvider> {
    provigil_common::ai::get_ai_providers(ch, UseCase::AriaChatResponse.tag()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(cid: &str, outcome: Option<&str>) -> Source {
        Source {
            community_id: cid.into(), verdict: "SUSPICIOUS".into(), reasoning: "r".into(),
            outcome: outcome.map(|s| s.into()), score: 0.8, src_ip: "10.0.0.5".into(),
            dst_ip: "203.0.113.9".into(), sensor_id: "s1".into(), generated_at: "t".into(),
        }
    }

    #[test]
    fn an_answer_may_only_cite_the_records_it_was_given() {
        let s = vec![src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", None)];
        assert!(answer_is_grounded("Yes, see 1:AAAAAAAAAAAAAAAAAAAAAAAA= which was a false positive.", &s));
        assert!(!answer_is_grounded("Yes, see 1:INVENTEDINVENTEDINVENTED= for details.", &s), "an invented citation is rejected");
        assert!(!answer_is_grounded("   ", &s), "an empty answer is rejected");
        assert!(answer_is_grounded("No matching record answers this.", &s), "an honest 'no' with no citation is fine");
    }

    #[test]
    fn no_records_means_no_ai_call_and_an_honest_message() {
        let a = compose("have we seen DNS tunneling?", vec![], "should never be used", "");
        assert_eq!((a.source, a.reason), ("records", "no_records"));
        assert!(a.answer.contains("No comparable past investigations"));
        assert!(a.sources.is_empty());
    }

    #[test]
    fn a_grounded_ai_answer_is_shown_and_an_ungrounded_one_is_not() {
        let s = vec![src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", Some("false_positive"))];
        let good = compose("q", s.clone(), "Yes: 1:AAAAAAAAAAAAAAAAAAAAAAAA= was a false positive.", "");
        assert_eq!(good.source, "ai");
        let bad = compose("q", s.clone(), "Yes: 1:MADEUPMADEUPMADEUPMADEUP= was an attack.", "");
        assert_eq!((bad.source, bad.reason), ("records", "rejected"), "the list is shown instead");
        assert_eq!(bad.sources.len(), 1, "the records are still there to read");
        let none = compose("q", s, "", "not_configured");
        assert_eq!((none.source, none.reason), ("records", "not_configured"));
    }

    #[test]
    fn the_prompt_contains_only_the_records_and_the_outcome_in_words() {
        let p = user_prompt("what happened?", &[src("1:AAAAAAAAAAAAAAAAAAAAAAAA=", Some("true_positive"))]);
        assert!(p.contains("1:AAAAAAAAAAAAAAAAAAAAAAAA=") && p.contains("closed as a confirmed attack"));
        assert!(SYSTEM_PROMPT.contains("ONLY the past investigation records"));
    }

    #[test]
    fn long_questions_are_cut() {
        assert_eq!(clean_question(&"x".repeat(1000)).chars().count(), MAX_QUESTION_CHARS);
    }
}
