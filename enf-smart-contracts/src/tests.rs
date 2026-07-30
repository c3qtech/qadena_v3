#![cfg(test)]
//! Unit tests for the ENF Electronic Notarial Book contract. These exercise the entry points
//! directly with mocked storage (no chain / no Docker), covering ENP registry uniqueness, the
//! UpdateEnp field-diff + index move + audit log, and per-roll_number entry sequencing.

use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
use cosmwasm_std::DepsMut;

use crate::contract::{execute, instantiate, query};
use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{DocRefs, Enp};

const CREATOR: &str = "creator";

fn setup(deps: DepsMut) {
    instantiate(deps, mock_env(), mock_info(CREATOR, &[]), InstantiateMsg {}).unwrap();
}

fn register_msg(roll: &str, email: &str, commission: &str) -> ExecuteMsg {
    ExecuteMsg::RegisterEnp {
        roll_number: roll.into(),
        email: email.into(),
        full_name: "Atty. Test".into(),
        commission_number: commission.into(),
    }
}

fn create_entry_msg(id: &str, roll: &str) -> ExecuteMsg {
    ExecuteMsg::CreateEntry {
        id: id.into(),
        enp: Enp {
            roll_number: roll.into(),
            email: "snap@x.com".into(),
            full_name: "Snapshot Name".into(),
            commission_number: "SNAP-C".into(),
        },
        entry_date: 1_700_000_000,
        status: "COMPLETED".into(),
        mode: "REN".into(),
        notarization_type: "ACKNOWLEDGMENT".into(),
        document_title: "Sample Deed".into(),
        document_type: "DEED_OF_SALE".into(),
        parties: vec![],
        references: DocRefs {
            document_id: "doc-1".into(),
            document_checksum: "abc123".into(),
            certificate: None,
        },
        cancellation_reason: None,
        cancelled_by: None,
    }
}

fn exec(deps: DepsMut, msg: ExecuteMsg) -> Result<cosmwasm_std::Response, ContractError> {
    execute(deps, mock_env(), mock_info(CREATOR, &[]), msg)
}

// ---- ENP registry: lookups ----

#[test]
fn register_then_lookup_by_roll_email_and_commission() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "enp@x.com", "2024-001")).unwrap();

    let by_roll = query::get_enp(deps.as_ref(), "12345".into()).unwrap();
    assert_eq!(by_roll.roll_number, "12345");
    assert_eq!(by_roll.email, "enp@x.com");
    assert_eq!(by_roll.commission_number, "2024-001");
    assert_eq!(by_roll.change_count, 0);

    // Both indexes resolve to the same record.
    let by_email = query::get_enp_by_email(deps.as_ref(), "enp@x.com".into()).unwrap();
    let by_comm = query::get_enp_by_commission(deps.as_ref(), "2024-001".into()).unwrap();
    assert_eq!(by_email.roll_number, "12345");
    assert_eq!(by_comm.roll_number, "12345");
}

// ---- ENP registry: uniqueness ----

#[test]
fn duplicate_roll_number_rejected() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "a@x.com", "C-1")).unwrap();
    let err = exec(deps.as_mut(), register_msg("12345", "b@x.com", "C-2")).unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { entity } if entity == "ENP"));
}

#[test]
fn duplicate_email_on_different_roll_rejected() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("111", "dup@x.com", "C-1")).unwrap();
    let err = exec(deps.as_mut(), register_msg("222", "dup@x.com", "C-2")).unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { entity } if entity == "ENP email"));
}

#[test]
fn duplicate_commission_on_different_roll_rejected() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("111", "a@x.com", "SHARED")).unwrap();
    let err = exec(deps.as_mut(), register_msg("222", "b@x.com", "SHARED")).unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { entity } if entity == "ENP commission number"));
}

#[test]
fn register_rejects_empty_required_fields() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());

    // Each required field, blanked in turn, is rejected with its name.
    let cases = [
        (register_msg("", "e@x.com", "C-1"), "roll_number"),
        (register_msg("12345", "", "C-1"), "email"),
        (register_msg("12345", "e@x.com", ""), "commission_number"),
    ];
    for (msg, field) in cases {
        let err = exec(deps.as_mut(), msg).unwrap_err();
        assert!(
            matches!(err, ContractError::Required { field: f } if f == field),
            "expected Required({field})"
        );
    }

    // full_name is required too (register_msg hard-codes it, so build a bare message).
    let err = exec(
        deps.as_mut(),
        ExecuteMsg::RegisterEnp {
            roll_number: "12345".into(),
            email: "e@x.com".into(),
            full_name: "   ".into(), // whitespace-only is still empty
            commission_number: "C-1".into(),
        },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::Required { field } if field == "full_name"));
}

#[test]
fn get_enps_paginates_over_the_registry() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("111", "a@x.com", "C-1")).unwrap();
    exec(deps.as_mut(), register_msg("222", "b@x.com", "C-2")).unwrap();
    exec(deps.as_mut(), register_msg("333", "c@x.com", "C-3")).unwrap();

    // First page of 2 (ordered by roll_number).
    let page1 = query::get_enps(deps.as_ref(), None, Some(2)).unwrap();
    assert_eq!(page1.total, 3);
    assert_eq!(page1.count, 2);
    assert!(page1.has_more);
    assert_eq!(page1.enps[0].roll_number, "111");
    assert_eq!(page1.enps[1].roll_number, "222");

    // Next page, using the last roll_number as the exclusive cursor.
    let page2 = query::get_enps(deps.as_ref(), Some("222".into()), Some(2)).unwrap();
    assert_eq!(page2.count, 1);
    assert!(!page2.has_more);
    assert_eq!(page2.enps[0].roll_number, "333");
}

// ---- ENP update: field-diff, index move, audit log ----

#[test]
fn update_enp_records_changes_and_moves_indexes() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "old@x.com", "2024-001")).unwrap();

    // Change email + commission (full_name unchanged).
    exec(
        deps.as_mut(),
        ExecuteMsg::UpdateEnp {
            roll_number: "12345".into(),
            email: "new@x.com".into(),
            full_name: "Atty. Test".into(),
            commission_number: "2026-009".into(),
            changed_by: "admin@x.com".into(),
        },
    )
    .unwrap();

    let rec = query::get_enp(deps.as_ref(), "12345".into()).unwrap();
    assert_eq!(rec.email, "new@x.com");
    assert_eq!(rec.commission_number, "2026-009");
    assert_eq!(rec.change_count, 1);

    // Old index keys no longer resolve; new ones do — same roll_number throughout.
    assert!(query::get_enp_by_email(deps.as_ref(), "old@x.com".into()).is_err());
    assert!(query::get_enp_by_commission(deps.as_ref(), "2024-001".into()).is_err());
    assert_eq!(
        query::get_enp_by_email(deps.as_ref(), "new@x.com".into()).unwrap().roll_number,
        "12345"
    );
    assert_eq!(
        query::get_enp_by_commission(deps.as_ref(), "2026-009".into()).unwrap().roll_number,
        "12345"
    );

    // Audit trail: one change record carrying both field changes.
    let changes = query::get_enp_changes(deps.as_ref(), "12345".into(), None, None).unwrap();
    assert_eq!(changes.total, 1);
    assert_eq!(changes.changes.len(), 1);
    let change = &changes.changes[0];
    assert_eq!(change.seq, 0);
    assert_eq!(change.changed_by, "admin@x.com");
    assert_eq!(change.changes.len(), 2);
    let fields: Vec<&str> = change.changes.iter().map(|f| f.field.as_str()).collect();
    assert!(fields.contains(&"email"));
    assert!(fields.contains(&"commission_number"));
    assert!(!fields.contains(&"full_name"));
}

#[test]
fn update_enp_noop_when_nothing_changes() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "e@x.com", "C-1")).unwrap();

    let res = exec(
        deps.as_mut(),
        ExecuteMsg::UpdateEnp {
            roll_number: "12345".into(),
            email: "e@x.com".into(),
            full_name: "Atty. Test".into(),
            commission_number: "C-1".into(),
            changed_by: "admin@x.com".into(),
        },
    )
    .unwrap();
    assert!(res.attributes.iter().any(|a| a.key == "changed" && a.value == "0"));

    let rec = query::get_enp(deps.as_ref(), "12345".into()).unwrap();
    assert_eq!(rec.change_count, 0);
    let changes = query::get_enp_changes(deps.as_ref(), "12345".into(), None, None).unwrap();
    assert_eq!(changes.total, 0);
    assert_eq!(changes.changes.len(), 0);
}

#[test]
fn update_unknown_enp_is_not_found() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    let err = exec(
        deps.as_mut(),
        ExecuteMsg::UpdateEnp {
            roll_number: "nope".into(),
            email: "e@x.com".into(),
            full_name: "x".into(),
            commission_number: "c".into(),
            changed_by: "admin@x.com".into(),
        },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::NotFound { entity } if entity == "ENP"));
}

#[test]
fn update_enp_email_collision_rejected() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("111", "a@x.com", "C-1")).unwrap();
    exec(deps.as_mut(), register_msg("222", "b@x.com", "C-2")).unwrap();

    // 222 tries to take 111's email.
    let err = exec(
        deps.as_mut(),
        ExecuteMsg::UpdateEnp {
            roll_number: "222".into(),
            email: "a@x.com".into(),
            full_name: "Atty. Test".into(),
            commission_number: "C-2".into(),
            changed_by: "admin@x.com".into(),
        },
    )
    .unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { entity } if entity == "ENP email"));
}

// ---- Notarial entries: registration requirement + sequencing ----

#[test]
fn create_entry_requires_registered_enp() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    let err = exec(deps.as_mut(), create_entry_msg("entry-1", "99999")).unwrap_err();
    assert!(matches!(err, ContractError::NotFound { entity } if entity == "ENP"));
}

#[test]
fn create_entry_rejects_empty_id_and_zero_date() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "e@x.com", "C-1")).unwrap();

    let err = exec(deps.as_mut(), create_entry_msg("", "12345")).unwrap_err();
    assert!(matches!(err, ContractError::Required { field } if field == "id"));

    let mut msg = create_entry_msg("entry-x", "12345");
    if let ExecuteMsg::CreateEntry { entry_date, .. } = &mut msg {
        *entry_date = 0;
    }
    let err = exec(deps.as_mut(), msg).unwrap_err();
    assert!(matches!(err, ContractError::Required { field } if field == "entry_date"));
}

#[test]
fn duplicate_entry_id_rejected() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "e@x.com", "C-1")).unwrap();
    exec(deps.as_mut(), create_entry_msg("entry-1", "12345")).unwrap();
    let err = exec(deps.as_mut(), create_entry_msg("entry-1", "12345")).unwrap_err();
    assert!(matches!(err, ContractError::AlreadyExists { entity } if entity == "NotarialBookEntry"));
}

#[test]
fn enf_seq_is_global_and_enp_seq_is_per_roll() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("111", "a@x.com", "C-1")).unwrap();
    exec(deps.as_mut(), register_msg("222", "b@x.com", "C-2")).unwrap();

    // Interleave entries across the two ENPs.
    exec(deps.as_mut(), create_entry_msg("e1", "111")).unwrap(); // enf 1, enp(111) 1
    exec(deps.as_mut(), create_entry_msg("e2", "222")).unwrap(); // enf 2, enp(222) 1
    exec(deps.as_mut(), create_entry_msg("e3", "111")).unwrap(); // enf 3, enp(111) 2

    let e1 = query::get_entry(deps.as_ref(), "e1".into()).unwrap();
    let e2 = query::get_entry(deps.as_ref(), "e2".into()).unwrap();
    let e3 = query::get_entry(deps.as_ref(), "e3".into()).unwrap();

    assert_eq!((e1.enf_seq, e1.enp_seq), (1, 1));
    assert_eq!((e2.enf_seq, e2.enp_seq), (2, 1));
    assert_eq!((e3.enf_seq, e3.enp_seq), (3, 2));

    assert_eq!(query::get_count(deps.as_ref()).unwrap().count, 3);
    assert_eq!(
        query::get_entries_by_enp(deps.as_ref(), "111".into(), None, None).unwrap().total,
        2
    );
}

#[test]
fn enp_seq_survives_identity_changes() {
    let mut deps = mock_dependencies();
    setup(deps.as_mut());
    exec(deps.as_mut(), register_msg("12345", "old@x.com", "2024-001")).unwrap();
    exec(deps.as_mut(), create_entry_msg("e1", "12345")).unwrap(); // enp_seq 1

    // Change email + commission; the per-roll sequence must not reset.
    exec(
        deps.as_mut(),
        ExecuteMsg::UpdateEnp {
            roll_number: "12345".into(),
            email: "new@x.com".into(),
            full_name: "Atty. Test".into(),
            commission_number: "2026-009".into(),
            changed_by: "admin@x.com".into(),
        },
    )
    .unwrap();

    exec(deps.as_mut(), create_entry_msg("e2", "12345")).unwrap(); // enp_seq 2, not reset

    assert_eq!(query::get_entry(deps.as_ref(), "e1".into()).unwrap().enp_seq, 1);
    assert_eq!(query::get_entry(deps.as_ref(), "e2".into()).unwrap().enp_seq, 2);
}
