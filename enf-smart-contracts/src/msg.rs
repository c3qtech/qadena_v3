use cosmwasm_schema::{cw_serde, QueryResponses};

use crate::state::{DocRefs, Enp, EnpChange, EnpRecord, NotarialBookEntry, Party};

#[cw_serde]
pub struct InstantiateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    // Register an ENP (notary) identity. Keyed by the permanent roll_number; rejects a duplicate
    // roll_number or an email/commission already used by a different ENP.
    RegisterEnp {
        roll_number: String,
        email: String,
        full_name: String,
        commission_number: String,
    },
    // Update the mutable identity fields (email, full_name, commission_number) of an ENP. The
    // roll_number identifies the ENP and never changes. Records a field-level audit entry.
    UpdateEnp {
        roll_number: String,
        email: String,
        full_name: String,
        commission_number: String,
        changed_by: String,
    },
    // Append one notarial-book entry. The contract assigns enf_seq (global) and enp_seq
    // (per enp.roll_number) and rejects a duplicate `id` (idempotent retries). Requires the ENP
    // to be registered.
    CreateEntry {
        id: String,
        enp: Enp,
        entry_date: u64,
        status: String,
        mode: String,
        notarization_type: String,
        document_title: String,
        document_type: String,
        parties: Vec<Party>,
        references: DocRefs,
        cancellation_reason: Option<String>,
        cancelled_by: Option<String>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // --- ENP registry ---
    #[returns(EnpRecord)]
    GetEnp { roll_number: String },
    #[returns(EnpRecord)]
    GetEnpByEmail { email: String },
    #[returns(EnpRecord)]
    GetEnpByCommission { commission_number: String },
    #[returns(PaginatedEnpsResponse)]
    GetEnps {
        start_after: Option<String>, // roll_number cursor (exclusive)
        limit: Option<u32>,
    },
    #[returns(PaginatedEnpChangesResponse)]
    GetEnpChanges {
        roll_number: String,
        start_after: Option<u64>, // change seq cursor (exclusive)
        limit: Option<u32>,
    },

    // --- Notarial book ---
    #[returns(NotarialBookEntry)]
    GetEntry { id: String },
    #[returns(NotarialBookEntry)]
    GetEntryByEnfSeq { enf_seq: u64 },
    #[returns(PaginatedEntriesResponse)]
    GetEntries {
        start_after: Option<u64>, // enf_seq cursor (exclusive)
        limit: Option<u32>,
    },
    #[returns(PaginatedEntriesResponse)]
    GetEntriesByEnp {
        roll_number: String,
        start_after: Option<u64>, // enp_seq cursor (exclusive)
        limit: Option<u32>,
    },
    #[returns(CountResponse)]
    GetCount {},
}

#[cw_serde]
pub struct PaginatedEntriesResponse {
    pub entries: Vec<NotarialBookEntry>,
    pub total: u64,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedEnpsResponse {
    pub enps: Vec<EnpRecord>,
    pub total: u64,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedEnpChangesResponse {
    pub changes: Vec<EnpChange>,
    pub total: u64,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct CountResponse {
    pub count: u64,
}
