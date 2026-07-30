use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

// Point-in-time ENP identity embedded in each notarial entry. The Roll of Attorney's number is
// permanent (assigned once at bar admission) and is the stable id; email/full_name/commission
// are captured as they were at the time of the entry.
#[cw_serde]
pub struct Enp {
    pub roll_number: String,       // stable id — never changes (the per-ENP sequence key)
    pub email: String,             // enf_users.email at entry time
    pub full_name: String,         // eKYC name, else enf_users First+Last
    pub commission_number: String, // enp_profiles.commission_number at entry time
}

// The ENP registry record (current identity), keyed by roll_number. email/full_name/
// commission_number are mutable; every change is recorded in ENP_CHANGES.
#[cw_serde]
pub struct EnpRecord {
    pub roll_number: String, // immutable id
    pub email: String,
    pub full_name: String,
    pub commission_number: String,
    pub change_count: u64,
    pub created_by: Addr,
    pub created_at: u64,
    pub updated_at: u64,
}

#[cw_serde]
pub struct FieldChange {
    pub field: String, // email | full_name | commission_number
    pub old: String,
    pub new: String,
}

// One audit record (the set of fields that changed in a single UpdateEnp).
#[cw_serde]
pub struct EnpChange {
    pub roll_number: String,
    pub seq: u64,
    pub changes: Vec<FieldChange>,
    pub changed_by: String,
    pub changed_at: u64,
}

// The notarial certificate (certificate_id -> notarial_certificates), denormalized. The FULL
// rendered certificate text is stored on chain so the entry is self-contained.
#[cw_serde]
pub struct CertificateRef {
    pub id: String,
    pub number: String,      // certificate_number (e.g. ENF-YYYY-xxxxx)
    pub cert_type: String,   // certificate_type (ACKNOWLEDGMENT, JURAT, ...)
    pub notarized_at: u64,   // notarial_certificates.notarized_at (unix seconds)
    pub content: String,     // full certificate_content (rendered jurat/acknowledgment text)
}

// The remaining foreign keys, denormalized to their meaningful values.
#[cw_serde]
pub struct DocRefs {
    pub document_id: String,
    pub document_checksum: String, // sha256 of the final PDF/A DocumentVersion
    pub certificate: Option<CertificateRef>, // None for CANCELLED/FAILED entries
}

#[cw_serde]
pub struct Party {
    pub full_name: String,
    pub role: String,
    pub email: String,
}

#[cw_serde]
pub struct NotarialBookEntry {
    pub id: String,                 // client-supplied UUID (= DB row id, the storage key)
    pub enf_seq: u64,               // chain-assigned global monotonic sequence
    pub enp_seq: u64,               // chain-assigned per-ENP monotonic sequence
    pub enp: Enp,
    pub entry_date: u64,            // unix seconds
    pub status: String,             // COMPLETED | CANCELLED | FAILED
    pub mode: String,               // IEN | REN
    pub notarization_type: String,  // ACKNOWLEDGMENT | JURAT
    pub document_title: String,
    pub document_type: String,
    pub parties: Vec<Party>,
    pub references: DocRefs,
    pub cancellation_reason: Option<String>,
    pub cancelled_by: Option<String>,
    pub created_by: Addr,
    pub created_at: u64,
}

// Notarial-book storage: the entry by id, plus global/per-ENP sequence indexes and counters.
pub const ENTRIES: Map<String, NotarialBookEntry> = Map::new("entries");     // id -> entry
pub const BY_ENF_SEQ: Map<u64, String> = Map::new("by_enf_seq");             // enf_seq -> id
pub const BY_ENP_SEQ: Map<(String, u64), String> = Map::new("by_enp_seq");   // (roll_number, enp_seq) -> id
pub const ENF_COUNT: Item<u64> = Item::new("enf_count");                     // global monotonic counter
pub const ENP_COUNT: Map<String, u64> = Map::new("enp_count");               // roll_number -> per-ENP counter

// ENP registry: the notary identity keyed by the permanent roll_number, with lookup indexes for
// the mutable email/commission_number, plus an append-only per-ENP change log (paper trail).
pub const ENPS: Map<String, EnpRecord> = Map::new("enps");                   // roll_number -> record
pub const ENP_TOTAL: Item<u64> = Item::new("enp_total");                     // count of registered ENPs
pub const ENP_BY_EMAIL: Map<String, String> = Map::new("enp_by_email");      // email -> roll_number
pub const ENP_BY_COMMISSION: Map<String, String> = Map::new("enp_by_comm");  // commission_number -> roll_number
pub const ENP_CHANGES: Map<(String, u64), EnpChange> = Map::new("enp_changes"); // (roll_number, seq) -> change
