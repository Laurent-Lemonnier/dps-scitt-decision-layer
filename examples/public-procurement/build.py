"""Public procurement in DPS: three decision records of one purchase (the decision to buy, the award, the review at
twelve months) and the action-binding attachment of the award's notification. Each record carries the price context it was
decided on (the estimate, the open-data comparables, the bids) and how it will be measured, so that waste shows: the
twelve-month review is a re_decision that states what was planned, what was paid and what is decided next.
Validates every record against the Core v5.0 schema and the attachment against action binding 0.3.0, and runs the action
binding reference check. No key: the attachment is unsigned (allowed); records carry their seal_hash."""
import base64
import hashlib
import importlib.util
import json
import os
import pathlib

from jsonschema import Draft202012Validator

REPO = pathlib.Path(os.environ.get("DPS_REPO", str(pathlib.Path(__file__).resolve().parents[3] / "standard")))  # a checkout of decision-provenance-standard/standard
HERE = pathlib.Path(__file__).resolve().parent
CHARTER = "CH-METROPOLE-ACHATS-2026"
OWNER = {"full_name": "Nadia Benali", "role": "Directrice de la commande publique", "employer": "Métropole (exemple)"}
ATTEST = {"attestor_full_name": OWNER["full_name"], "attestor_role_title": OWNER["role"], "attestor_employer": OWNER["employer"],
          "jurisdiction": "EU", "attestation_language_version": "v5.0", "attestor_capacity": "employee"}


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def compact(doc):
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sealed(record):
    record = dict(record, seal_hash="0" * 64)
    record["seal_hash"] = sha256(compact(record))
    return record


def attestation(when, text):
    return {**ATTEST, "attestation_timestamp": when, "attestation_text_signed": text}


# ---- 1. The decision to buy: a maintenance contract for 420 municipal vehicles, priced against open data
D1 = sealed({
    "decision_id": "DR-2026-0071", "charter_id": CHARTER, "record_type": "decision", "record_state": "closed",
    "dispatch_mode": "mode-1-with-embedded-mode-2-summary", "created_at": "2026-02-10T09:00:00Z",
    "altitude": "function-leader",
    "decision_statement": "Launch an open procedure for the preventive and corrective maintenance of the 420 light "
                          "vehicles of the fleet, 36 months, estimated at 1,140,000 EUR excl. VAT (905 EUR per vehicle "
                          "per year), against a current spend of 1,410,000 EUR over the last 36 months.",
    "context_at_decision": "The current contract (2023-2026) ends on 2026-09-30. Spend over its 36 months: 1,410,000 EUR, "
                           "1,119 EUR per vehicle per year. The fleet office's assistant compared it with 14 contracts of "
                           "the same object and size published in the essential procurement data (DECP) 2024-2025: median "
                           "890 EUR per vehicle per year, first quartile 760, third quartile 1,010. The assistant's "
                           "estimate for this fleet: 905 EUR, given the share of utility vehicles (38 %).",
    "options_considered": [
        "Open procedure, one lot, 36 months, estimate 1,140,000 EUR (chosen): the comparables show a market price about "
        "20 % below the current spend; a single lot keeps one accountable maintainer per vehicle.",
        "Renew with the current holder by negotiated procedure: not available at this amount, and the price is the problem.",
        "Join the departmental purchasing group's maintenance contract: 940 EUR per vehicle per year in its 2025 price "
        "list, but a 48-month commitment and no utility-vehicle rate; kept as the fallback if the procedure fails.",
        "Two lots (passenger cars, utility vehicles): would let specialists bid, but doubles the management; revisit at "
        "the next renewal with this contract's data."],
    "required_inputs_used": ["Spend ledger 2023-2026 of the current contract (1,410,000 EUR, 1,119 EUR per vehicle per year)",
                             "DECP extract 2024-2025, 14 comparable contracts (median 890, Q1 760, Q3 1,010 EUR per vehicle per year)",
                             "Fleet inventory 2026-01: 420 vehicles, 38 % utility", "Purchasing group price list 2025 (940 EUR)"],
    "assumptions_depended_on": ["The fleet stays within 400 to 440 vehicles over 36 months.",
                                "The comparables' scope (preventive and corrective, parts included) matches this need."],
    "success_criteria": ["Awarded price at or below 1,140,000 EUR over 36 months (905 EUR per vehicle per year).",
                         "Actual spend at 12 months at or below 390,000 EUR, measured on the invoice ledger.",
                         "Vehicle availability at or above 96 %, measured monthly by the fleet office."],
    "accountable_owner": OWNER, "decision_class": "procurement-launch",
    "drafting_authority": {"deployer_role_pointer": "urn:metropole:role:achats-assistant", "system_name": "achats-assistant",
                           "version": "2"},
    "consent_posture": {"posture_class": "not-applicable: no personal data"},
    "affirmation_record": {"timestamp": "2026-02-12T16:30:00Z", "actor_identity": "dir-commande-publique",
                           "method": "signed approval in the procurement console"},
    "mode_classification_attestation": attestation("2026-02-12T16:35:00Z",
        "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary under charter "
        "CH-METROPOLE-ACHATS-2026: the purchasing assistant (achats-assistant, version 2) drafted the estimate from the "
        "spend ledger and the DECP comparables; I reviewed the four options recorded here, chose the open procedure, and I "
        "am the accountable owner of this decision in my capacity as an employee of the Métropole."),
    "accountable_owner_signoff": {"signed_by": "dir-commande-publique", "signed_at": "2026-02-12T16:35:00Z"},
    "re_decision_trigger": "No offer at or below the estimate; or a fleet change beyond 10 %; or the 12-month review.",
    "record_location": "urn:metropole:decision-records:DR-2026-0071",
    "related_decisions": [], "seal_algorithm": "SHA-256", "supersedes": None, "closed_at": "2026-02-12T16:35:00Z",
})

# ---- 2. The award: four bids, the prices as received, the analysis, the choice
D2 = sealed({
    "decision_id": "DR-2026-0142", "charter_id": CHARTER, "record_type": "decision", "record_state": "closed",
    "dispatch_mode": "mode-1-with-embedded-mode-2-summary", "created_at": "2026-06-18T10:00:00Z",
    "altitude": "function-leader",
    "decision_statement": "Award the fleet maintenance contract (36 months) to bidder B for 1,062,000 EUR excl. VAT "
                          "(843 EUR per vehicle per year), ranked first on the weighted criteria (price 60, service 40).",
    "context_at_decision": "Four bids received by 2026-05-29: A 1,236,000 EUR (981 per vehicle per year), B 1,062,000 "
                           "(843), C 1,004,000 (797), D 1,318,000 (1,046). The assistant's analysis flagged C as "
                           "abnormally low on parts (parts priced 31 % under the DECP median); C's written explanation "
                           "(2026-06-09) did not account for the parts price, so C was rejected as abnormally low after "
                           "the adversarial procedure. B scores 60/60 on price among the remaining bids and 34/40 on "
                           "service (response time 4 h, replacement vehicles). Estimate was 1,140,000 EUR.",
    "options_considered": [
        "Award to B at 1,062,000 EUR (chosen): first on the weighted criteria once C is rejected; 7 % under the estimate, "
        "25 % under the current spend.",
        "Award to C at 1,004,000 EUR: lowest price, but abnormally low on parts and the explanation does not hold; the "
        "risk is unpaid parts and a failed contract.",
        "Award to A at 1,236,000 EUR: best service score (38/40) but 16 % above B and 8 % above the estimate.",
        "Declare the procedure unsuccessful and join the purchasing group (940 EUR): more expensive than B."],
    "required_inputs_used": ["The four bids as opened (2026-05-29), price schedules included",
                             "Analysis report of 2026-06-15 (criteria, scores, abnormally-low check against DECP medians)",
                             "C's explanation of 2026-06-09", "Decision DR-2026-0071 (estimate and criteria)"],
    "assumptions_depended_on": ["B's price schedule holds for 36 months under the revision formula of the contract."],
    "success_criteria": ["Notification within 15 days of the award.",
                         "Actual spend at 12 months at or below 354,000 EUR (one third of the award), on the invoice ledger.",
                         "Availability at or above 96 % monthly."],
    "accountable_owner": OWNER, "decision_class": "procurement-award",
    "drafting_authority": {"deployer_role_pointer": "urn:metropole:role:achats-assistant", "system_name": "achats-assistant",
                           "version": "2"},
    "consent_posture": {"posture_class": "not-applicable: bidders are legal persons"},
    "affirmation_record": {"timestamp": "2026-06-19T11:00:00Z", "actor_identity": "dir-commande-publique",
                           "method": "signed approval in the procurement console"},
    "mode_classification_attestation": attestation("2026-06-19T11:05:00Z",
        "I attest that this decision record was dispatched in mode-1 with an embedded mode-2 summary under charter "
        "CH-METROPOLE-ACHATS-2026: the purchasing assistant (achats-assistant, version 2) drafted the analysis of the four "
        "bids and the abnormally-low check; the commission heard C's explanation; I reviewed the four options recorded "
        "here, approved the award to B, and I am the accountable owner of this decision in my capacity as an employee "
        "of the Métropole."),
    "accountable_owner_signoff": {"signed_by": "dir-commande-publique", "signed_at": "2026-06-19T11:05:00Z"},
    "re_decision_trigger": "A rejected bidder's challenge; B's withdrawal; or the 12-month review.",
    "record_location": "urn:metropole:decision-records:DR-2026-0142",
    "related_decisions": ["DR-2026-0071"], "seal_algorithm": "SHA-256", "supersedes": None,
    "closed_at": "2026-06-19T11:05:00Z",
})

# ---- 3. The review at twelve months: a re_decision that states what was planned, what was paid, what is decided
D3 = sealed({
    "decision_id": "DR-2027-0210", "charter_id": CHARTER, "record_type": "re_decision", "record_state": "closed",
    "dispatch_mode": "mode-1-with-embedded-mode-2-summary", "created_at": "2027-10-05T09:00:00Z",
    "altitude": "function-leader",
    "decision_statement": "Keep the contract with B unchanged after the 12-month review: actual spend 338,400 EUR "
                          "against 354,000 planned (-4.4 %), availability 96.8 %; no revision of the price schedule; "
                          "the fleet office's planned 2027 scope extension (28 vehicles) goes through the contract's "
                          "unit prices, not a new purchase.",
    "context_at_decision": "Months 1 to 12 (2026-10 to 2027-09): invoices 338,400 EUR, of which parts 141,200 (B's "
                           "schedule held; no abnormally-low pattern); 419 vehicles on average; availability 96.8 % "
                           "(target 96 %); 2 penalties applied (response time), 1,900 EUR. Compared with the last 12 "
                           "months of the previous contract (471,000 EUR, 420 vehicles): 28 % less for the same scope. "
                           "The DECP 2026 median for comparable contracts moved to 915 EUR per vehicle per year; B is at "
                           "843.",
    "options_considered": [
        "Keep the contract unchanged and route the 28-vehicle extension through its unit prices (chosen): the price and "
        "the service hold; the extension stays within the contract's 10 % clause.",
        "Negotiate a lower price given the volume: the price is already 8 % under the market median; a renegotiation "
        "would risk the service level for little gain.",
        "Re-tender early to split into two lots: no reason to: the single lot performs."],
    "required_inputs_used": ["Invoice ledger 2026-10 to 2027-09 (338,400 EUR)", "Fleet office availability reports (12 months)",
                             "Penalty register (2 entries)", "DECP 2026 extract (median 915 EUR per vehicle per year)",
                             "Decisions DR-2026-0071 and DR-2026-0142 (plan and criteria)"],
    "assumptions_depended_on": ["The 28 added vehicles are of the same mix as the fleet."],
    "success_criteria": ["Spend at 24 months at or below 708,000 EUR cumulated.", "Availability at or above 96 %."],
    "accountable_owner": OWNER, "decision_class": "procurement-review",
    "drafting_authority": {"deployer_role_pointer": "urn:metropole:role:achats-assistant", "system_name": "achats-assistant",
                           "version": "3"},
    "consent_posture": {"posture_class": "not-applicable: no personal data"},
    "affirmation_record": {"timestamp": "2027-10-06T15:00:00Z", "actor_identity": "dir-commande-publique",
                           "method": "signed approval in the procurement console"},
    "mode_classification_attestation": attestation("2027-10-06T15:05:00Z",
        "I attest that this re-decision record was dispatched in mode-1 with an embedded mode-2 summary under charter "
        "CH-METROPOLE-ACHATS-2026: the purchasing assistant (achats-assistant, version 3) drafted the comparison of the "
        "planned and actual spend from the invoice ledger and the availability reports; I reviewed the three options "
        "recorded here, kept the contract unchanged, and I am the accountable owner of this decision in my capacity as "
        "an employee of the Métropole."),
    "accountable_owner_signoff": {"signed_by": "dir-commande-publique", "signed_at": "2027-10-06T15:05:00Z"},
    "re_decision_trigger": "The 24-month review; a spend drift beyond 5 % of plan in any quarter; availability under 95 %.",
    "record_location": "urn:metropole:decision-records:DR-2027-0210",
    "related_decisions": ["DR-2026-0071", "DR-2026-0142"], "seal_algorithm": "SHA-256", "supersedes": None,
    "closed_at": "2027-10-06T15:05:00Z",
})

# ---- the action the award executes: the notification of the contract to B, as the approver saw it
spec = {"operation": "contract.notify", "target": "urn:metropole:marche:2026-071",
        "parameters": {"holder": "bidder B (SIREN redacted in this example)", "amount_excl_vat_eur": "1062000.00",
                       "duration_months": 36, "price_schedule_digest": "sha256:7c1e8a0f4b2d3c5e6f7081920a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d",
                       "revision_formula": "annual, index TP-xx (example)", "penalties": "response time > 4 h: 950 EUR"},
        "input_version_refs": ["urn:metropole:analysis-report:2026-071#v3", "urn:metropole:bids:2026-071#opened-2026-05-29"],
        "policy_version": "urn:metropole:procurement-policy:2026-1"}
spec_bytes = compact(spec)
sd = sha256(spec_bytes)
attachment = {
    "profile": "dps-action-binding", "profile_version": "0.3.0", "decision_id": D2["decision_id"],
    "action_specifications": [{"spec_digest": sd, "representation": {"kind": "original_bytes", "media_type": "application/json"},
                               "content": {"availability": "available", "bytes_b64": base64.b64encode(spec_bytes).decode("ascii")},
                               "summary": {"operation": spec["operation"], "target": spec["target"],
                                           "policy_version": spec["policy_version"], "input_version_refs": spec["input_version_refs"]}}],
    "stages": [
        {"stage_id": "p1", "kind": "proposal", "at": "2026-06-18T10:30:00Z", "origin": "ai", "spec_digest": sd,
         "deployer_role_pointer": "urn:metropole:role:achats-assistant", "system_name": "achats-assistant", "version": "2"},
        {"stage_id": "v1", "kind": "review", "at": "2026-06-19T10:50:00Z", "reviewer_ref": "dir-commande-publique",
         "shown_spec_digest": sd, "proposal_ref": "p1", "shown_view_ref": "urn:metropole:procurement-console:view:2026-071"},
        {"stage_id": "o1", "kind": "outcome", "at": "2026-06-19T11:00:00Z", "review_ref": "v1", "outcome": "approved",
         "actor_ref": "dir-commande-publique", "method": "signed approval in the procurement console", "approved_spec_digest": sd,
         "authority": {"authority_ref": "urn:metropole:charter:CH-METROPOLE-ACHATS-2026#award-delegation"},
         "rationale": {"timing": "contemporaneous", "ai_assisted": False, "recorded_at": "2026-06-19T11:00:00Z",
                       "text_ref": "urn:metropole:rationale:2026-071"},
         "core_ref": {"field": "affirmation_record"}},
        {"stage_id": "q1", "kind": "request", "at": "2026-06-22T09:00:00Z", "request_id": "urn:metropole:notify:2026-071",
         "authorised_by": "o1", "spec_digest": sd, "requested_by": "urn:metropole:service:procurement-platform"},
        {"stage_id": "c1", "kind": "recheck", "at": "2026-06-22T09:00:05Z", "request_ref": "q1", "result": "authorised",
         "authority_source_ref": "urn:metropole:delegation-register:snapshot:2026-06-22"},
        {"stage_id": "x1", "kind": "attempt", "at": "2026-06-22T09:00:10Z", "request_ref": "q1", "recheck_ref": "c1", "spec_digest": sd,
         "executor_ref": "urn:metropole:service:procurement-platform", "trace_refs": ["urn:metropole:trace:2026-071"]},
        {"stage_id": "r1", "kind": "result", "at": "2026-06-22T09:01:30Z", "attempt_ref": "x1", "observed": "succeeded",
         "basis": "target_response", "evidence_ref": "urn:metropole:notify:2026-071:acknowledgement"},
    ],
}

rec_schema = json.load(open(REPO / "standard/v5.0/schemas/decision-record.schema.json"))
att_schema = json.load(open(REPO / "extensions/action-binding/schemas/execution-evidence.schema.json"))
rv = Draft202012Validator(rec_schema)
spec_ab = importlib.util.spec_from_file_location("ab", REPO / "extensions/action-binding/tests/run_checks.py")
ab = importlib.util.module_from_spec(spec_ab)
spec_ab.loader.exec_module(ab)
out = {"records": {}, "attachment_schema_errors": [e.message for e in Draft202012Validator(att_schema).iter_errors(attachment)]}
for r in (D1, D2, D3):
    (HERE / f"{r['decision_id']}.json").write_bytes(compact(r))
    out["records"][r["decision_id"]] = {"schema_errors": [e.message for e in rv.iter_errors(r)], "seal_hash": r["seal_hash"],
                                        "record_type": r["record_type"]}
(HERE / "award-notification-attachment.json").write_bytes(compact(attachment))
binding = ab.check_attachment(attachment, compact(D2))
out["attachment_digest"] = sha256(compact(attachment))
out["binding_check"] = {k: (v[0] if isinstance(v, list) and v and isinstance(v[0], str) else v) for k, v in binding.items()
                        if k in ("specification_digests", "record_statements", "action_binding", "stage_order",
                                 "authorisation_recheck", "observed_results", "rationale_provenance", "execution_state")}
out["measure"] = {"planned_36_months_eur": 1140000, "awarded_eur": 1062000, "previous_36_months_eur": 1410000,
                  "actual_12_months_eur": 338400, "planned_12_months_eur": 354000,
                  "saving_vs_previous_pct": round(100 * (1 - 1062000 / 1410000), 1)}
json.dump(out, open(HERE / "summary.json", "w"), indent=1, ensure_ascii=False)
print(json.dumps(out, indent=1, ensure_ascii=False))
