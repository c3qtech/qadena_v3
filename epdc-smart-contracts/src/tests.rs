use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::from_json;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::contract::{execute, instantiate, query};
use crate::msg::{
    Attestation, ExecuteMsg, HolderResponse, InstantiateMsg, QueryMsg, QuorumRulesResponse,
};
use crate::state::RegisterEvent;
use crate::ContractError;

const OPERATOR: &str = "operator";

struct TestAttestor {
    addr: &'static str,
    key: SigningKey,
}

impl TestAttestor {
    fn new(addr: &'static str, seed: u8) -> Self {
        let mut bytes = [seed; 32];
        bytes[31] = seed.wrapping_add(1); // avoid the all-zero / degenerate keys
        Self {
            addr,
            key: SigningKey::from_bytes(&bytes.into()).unwrap(),
        }
    }

    fn pubkey_hex(&self) -> String {
        hex::encode(self.key.verifying_key().to_encoded_point(true).as_bytes())
    }

    fn sign(&self, digest: &[u8; 32]) -> String {
        let sig: Signature = self.key.sign_prehash(digest).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        hex::encode(sig.to_bytes())
    }
}

fn digest_of(payload: &str) -> ([u8; 32], String) {
    let d: [u8; 32] = Sha256::digest(payload.as_bytes()).into();
    (d, hex::encode(d))
}

fn setup() -> cosmwasm_std::OwnedDeps<
    cosmwasm_std::MemoryStorage,
    cosmwasm_std::testing::MockApi,
    cosmwasm_std::testing::MockQuerier,
> {
    let mut deps = mock_dependencies();
    instantiate(
        deps.as_mut(),
        mock_env(),
        mock_info(OPERATOR, &[]),
        InstantiateMsg {},
    )
    .unwrap();
    deps
}

fn register(deps: &mut cosmwasm_std::OwnedDeps<
    cosmwasm_std::MemoryStorage,
    cosmwasm_std::testing::MockApi,
    cosmwasm_std::testing::MockQuerier,
>, a: &TestAttestor, class: &str) {
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OPERATOR, &[]),
        ExecuteMsg::RegisterAttestor {
            addr: a.addr.to_string(),
            class: class.to_string(),
            name: format!("{} inc", a.addr),
            pubkey_hex: a.pubkey_hex(),
        },
    )
    .unwrap();
}

fn append(
    deps: &mut cosmwasm_std::OwnedDeps<
        cosmwasm_std::MemoryStorage,
        cosmwasm_std::testing::MockApi,
        cosmwasm_std::testing::MockQuerier,
    >,
    id: &str,
    instrument_ref: &str,
    event_type: &str,
    digest_hex: &str,
    attestations: Vec<Attestation>,
) -> Result<cosmwasm_std::Response, ContractError> {
    execute(
        deps.as_mut(),
        mock_env(),
        mock_info(OPERATOR, &[]),
        ExecuteMsg::AppendEvent {
            id: id.to_string(),
            instrument_ref: instrument_ref.to_string(),
            event_type: event_type.to_string(),
            digest: digest_hex.to_string(),
            reason_code: None,
            dsvs_doc_id: None,
            attestations,
        },
    )
}

#[test]
fn append_assigns_sequences_and_rejects_duplicate_id() {
    let mut deps = setup();
    let (_, d1) = digest_of("event-1");
    let (_, d2) = digest_of("event-2");

    append(&mut deps, "e1", "inst-A", "INSTRUMENT_ISSUED", &d1, vec![]).unwrap();
    append(&mut deps, "e2", "inst-A", "ATTEMPT_CLOSED", &d2, vec![]).unwrap();

    let ev: RegisterEvent = from_json(
        query(deps.as_ref(), mock_env(), QueryMsg::GetEvent { id: "e2".into() }).unwrap(),
    )
    .unwrap();
    assert_eq!(ev.seq, 2);
    assert_eq!(ev.instrument_seq, 2);

    // Idempotency: the saga re-drive path — duplicate id must be refused, and
    // refused as AlreadyExists specifically, because the sweeper reads that
    // error as "anchored already".
    let err = append(&mut deps, "e1", "inst-A", "INSTRUMENT_ISSUED", &d1, vec![]).unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { .. }));
}

#[test]
fn quorum_event_refuses_without_signatures() {
    let mut deps = setup();
    let (_, d) = digest_of("dishonour");
    let err = append(&mut deps, "e1", "inst-A", "DISHONOUR_DECLARED", &d, vec![]).unwrap_err();
    assert!(matches!(err, ContractError::QuorumNotMet { .. }));
}

#[test]
fn operator_signature_never_satisfies_disinterested_minimum() {
    let mut deps = setup();
    let op = TestAttestor::new("op-node", 11);
    let op2 = TestAttestor::new("op-node-2", 13);
    register(&mut deps, &op, "OPERATOR");
    register(&mut deps, &op2, "OPERATOR");

    let (raw, d) = digest_of("dishonour");
    // Two valid operator signatures: total quorum is met (2 >= 2), but the
    // disinterested minimum cannot be — this is THE structural exclusion.
    let atts = vec![
        Attestation { attestor: op.addr.into(), signature_hex: op.sign(&raw) },
        Attestation { attestor: op2.addr.into(), signature_hex: op2.sign(&raw) },
    ];
    let err = append(&mut deps, "e1", "inst-A", "DISHONOUR_DECLARED", &d, atts).unwrap_err();
    match err {
        ContractError::QuorumNotMet { valid, disinterested, .. } => {
            assert_eq!(valid, 2);
            assert_eq!(disinterested, 0);
        }
        other => panic!("expected QuorumNotMet, got {:?}", other),
    }
}

#[test]
fn quorum_met_with_disinterested_signature() {
    let mut deps = setup();
    let drawee = TestAttestor::new("drawee-coop", 21);
    let uni = TestAttestor::new("state-university", 22);
    register(&mut deps, &drawee, "DRAWEE");
    register(&mut deps, &uni, "DISINTERESTED");

    let (raw, d) = digest_of("dishonour");
    let atts = vec![
        Attestation { attestor: drawee.addr.into(), signature_hex: drawee.sign(&raw) },
        Attestation { attestor: uni.addr.into(), signature_hex: uni.sign(&raw) },
    ];
    append(&mut deps, "e1", "inst-A", "DISHONOUR_DECLARED", &d, atts).unwrap();

    let ev: RegisterEvent = from_json(
        query(deps.as_ref(), mock_env(), QueryMsg::GetEvent { id: "e1".into() }).unwrap(),
    )
    .unwrap();
    assert_eq!(ev.attestations.len(), 2);
    // Classes are recorded as-at signing, for the certificate's node roster.
    assert_eq!(ev.attestations[1].class_at_signing.as_str(), "DISINTERESTED");
}

#[test]
fn invalid_signature_is_a_hard_error() {
    let mut deps = setup();
    let uni = TestAttestor::new("state-university", 22);
    register(&mut deps, &uni, "DISINTERESTED");

    let (_, d) = digest_of("event");
    let (other_raw, _) = digest_of("some other payload");
    let atts = vec![Attestation {
        attestor: uni.addr.into(),
        signature_hex: uni.sign(&other_raw), // signs the wrong digest
    }];
    // Even on a NON-quorum event type, a bad signature is refused outright —
    // never recorded, never silently dropped.
    let err = append(&mut deps, "e1", "inst-A", "INSTRUMENT_ISSUED", &d, atts).unwrap_err();
    assert!(format!("{}", err).contains("invalid signature"));
}

#[test]
fn holder_compare_and_set_prevents_double_assignment() {
    let mut deps = setup();

    let set = |deps: &mut cosmwasm_std::OwnedDeps<_, _, _>, holder: &str, prev: Option<&str>| {
        execute(
            deps.as_mut(),
            mock_env(),
            mock_info(OPERATOR, &[]),
            ExecuteMsg::SetHolder {
                instrument_ref: "inst-A".into(),
                holder: holder.into(),
                prev_holder: prev.map(|s| s.to_string()),
            },
        )
    };

    set(&mut deps, "payee-1", None).unwrap();
    // A second assignment claiming the slot is empty must fail...
    let err = set(&mut deps, "financier-2", None).unwrap_err();
    assert!(matches!(err, ContractError::HolderMismatch { .. }));
    // ...and one naming the true current holder succeeds.
    set(&mut deps, "financier-2", Some("payee-1")).unwrap();

    let resp: HolderResponse = from_json(
        query(deps.as_ref(), mock_env(), QueryMsg::GetHolder { instrument_ref: "inst-A".into() })
            .unwrap(),
    )
    .unwrap();
    assert_eq!(resp.holder.as_deref(), Some("financier-2"));
}

#[test]
fn quorum_rules_are_exposed_and_operator_excluded() {
    let deps = setup();
    let rules: QuorumRulesResponse =
        from_json(query(deps.as_ref(), mock_env(), QueryMsg::GetQuorumRules {}).unwrap()).unwrap();
    assert_eq!(rules.quorum_min, 2);
    assert_eq!(rules.disinterested_min, 1);
    assert!(!rules.operator_counts_as_disinterested);
}

#[test]
fn only_operator_registers_attestors() {
    let mut deps = setup();
    let uni = TestAttestor::new("state-university", 22);
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("someone-else", &[]),
        ExecuteMsg::RegisterAttestor {
            addr: uni.addr.to_string(),
            class: "DISINTERESTED".to_string(),
            name: "uni".to_string(),
            pubkey_hex: uni.pubkey_hex(),
        },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::Unauthorized {}));
}

#[test]
fn only_operator_appends_events() {
    let mut deps = setup();
    let (_, digest_hex) = digest_of("event-by-a-stranger");
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("someone-else", &[]),
        ExecuteMsg::AppendEvent {
            id: "evt-x".into(),
            instrument_ref: "inst-A".into(),
            event_type: "INSTRUMENT_ISSUED".into(),
            digest: digest_hex,
            reason_code: None,
            dsvs_doc_id: None,
            attestations: vec![],
        },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::Unauthorized {}));
}

#[test]
fn only_operator_sets_holder() {
    let mut deps = setup();
    let err = execute(
        deps.as_mut(),
        mock_env(),
        mock_info("someone-else", &[]),
        ExecuteMsg::SetHolder { instrument_ref: "inst-A".into(), holder: "thief".into(), prev_holder: None },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::Unauthorized {}));
}
