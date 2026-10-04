use cosmwasm_schema::{cw_serde, QueryResponses};

use crate::state::{AttestorRecord, RegisterEvent};

#[cw_serde]
pub struct InstantiateMsg {}

/// Upgrades the code in place (wasmd migrate, by the contract admin). Nothing to carry over yet.
#[cw_serde]
pub struct MigrateMsg {}

/// An attestor countersignature submitted with an event: a secp256k1
/// signature (64-byte r||s, hex) over the raw 32-byte event digest.
#[cw_serde]
pub struct Attestation {
    pub attestor: String, // roster address
    pub signature_hex: String,
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Register or update an attestor. Operator-only. The class is data; the
    /// arithmetic that decides what a class may count toward is compiled
    /// (state::AttestorClass) and no message can reach it.
    RegisterAttestor {
        addr: String,
        class: String, // OPERATOR | DRAWEE | DISINTERESTED
        name: String,
        pubkey_hex: String, // 33-byte compressed secp256k1, hex
    },
    /// Deactivate an attestor (kept in the roster; history stands).
    DeactivateAttestor { addr: String },
    /// Append one register event. Idempotent by `id` — a duplicate id is
    /// rejected with AlreadyExists, which a re-driving saga treats as done.
    /// Attestations are verified against the roster; invalid ones are
    /// rejected outright (never silently dropped). Event types listed in
    /// state::QUORUM_EVENT_TYPES refuse to append unless the verified set
    /// meets QUORUM_MIN and DISINTERESTED_MIN.
    AppendEvent {
        id: String,
        instrument_ref: String,
        event_type: String,
        digest: String, // sha256 hex, 64 chars
        reason_code: Option<String>,
        dsvs_doc_id: Option<String>,
        attestations: Vec<Attestation>,
    },
    /// Compare-and-set the single holder of an instrument (BRD FR-902).
    /// Fails unless the current holder equals `prev_holder` (None = unset).
    SetHolder {
        instrument_ref: String,
        holder: String,
        prev_holder: Option<String>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(RegisterEvent)]
    GetEvent { id: String },
    #[returns(RegisterEvent)]
    GetEventBySeq { seq: u64 },
    #[returns(PaginatedEventsResponse)]
    GetEvents {
        start_after: Option<u64>, // seq cursor (exclusive)
        limit: Option<u32>,
    },
    #[returns(PaginatedEventsResponse)]
    GetEventsByInstrument {
        instrument_ref: String,
        start_after: Option<u64>, // instrument_seq cursor (exclusive)
        limit: Option<u32>,
    },
    #[returns(AttestorsResponse)]
    GetAttestors {},
    #[returns(HolderResponse)]
    GetHolder { instrument_ref: String },
    #[returns(CountResponse)]
    GetCount {},
    /// The compiled quorum rules, read-only — exposed so a verifier can see
    /// them; there is no message that writes them.
    #[returns(QuorumRulesResponse)]
    GetQuorumRules {},
}

#[cw_serde]
pub struct PaginatedEventsResponse {
    pub events: Vec<RegisterEvent>,
    pub total: u64,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct AttestorsResponse {
    pub attestors: Vec<AttestorRecord>,
}

#[cw_serde]
pub struct HolderResponse {
    pub instrument_ref: String,
    pub holder: Option<String>,
}

#[cw_serde]
pub struct CountResponse {
    pub count: u64,
}

#[cw_serde]
pub struct QuorumRulesResponse {
    pub quorum_min: u32,
    pub disinterested_min: u32,
    pub quorum_event_types: Vec<String>,
    /// Always false, compiled: whether an operator signature can satisfy the
    /// disinterested minimum.
    pub operator_counts_as_disinterested: bool,
}
