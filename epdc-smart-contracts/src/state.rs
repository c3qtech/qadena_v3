use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};

// e-PDC register: the append-only, hash-only lifecycle register for dated
// payment instructions. G1 applies in full — an event carries digests and
// opaque references only; names, amounts, dates and contacts never reach this
// contract. The off-chain store holds the preimages; anyone holding the
// disclosed fields recomputes the digest and compares.

// ---------------------------------------------------------------------------
// Attestor classes and the operator-exclusion rule (BRD FR-1003 / gate G4).
//
// The rule "an OPERATOR-class signature can never satisfy the disinterested
// minimum" is a compiled match arm in `AttestorClass::counts_as_disinterested`
// — governed by no parameter, stored in no state, exposed at no interface.
// There is deliberately no ExecuteMsg that can change QUORUM_MIN,
// DISINTERESTED_MIN or the class arithmetic; changing them is a contract
// migration, visible on chain as a new code id.
// ---------------------------------------------------------------------------

/// Minimum count of valid attestor signatures for a quorum-gated event.
pub const QUORUM_MIN: u32 = 2;
/// Of those, the minimum that must come from DISINTERESTED-class attestors.
pub const DISINTERESTED_MIN: u32 = 1;

/// Event types that refuse to append without quorum. Everything else is an
/// ordinary lifecycle fact appended by the orchestrator (attestations are
/// still verified and recorded when supplied — they just aren't required).
pub const QUORUM_EVENT_TYPES: [&str; 3] = [
    "DISHONOUR_DECLARED",
    "CERTIFICATE_ASSEMBLED",
    "SUPERSEDING_CERTIFICATE",
];

#[cw_serde]
pub enum AttestorClass {
    Operator,
    Drawee,
    Disinterested,
}

impl AttestorClass {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "OPERATOR" => Some(Self::Operator),
            "DRAWEE" => Some(Self::Drawee),
            "DISINTERESTED" => Some(Self::Disinterested),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Operator => "OPERATOR",
            Self::Drawee => "DRAWEE",
            Self::Disinterested => "DISINTERESTED",
        }
    }

    /// THE rule. An operator signature counts toward the total quorum but is
    /// structurally incapable of counting toward the disinterested minimum.
    pub fn counts_as_disinterested(&self) -> bool {
        match self {
            Self::Operator => false, // compiled constant — no parameter, no interface
            Self::Drawee => false,   // interested party to the instrument
            Self::Disinterested => true,
        }
    }
}

#[cw_serde]
pub struct Config {
    /// The instantiating operator. May register attestors; its own signatures
    /// never satisfy the disinterested minimum (see AttestorClass).
    pub operator: Addr,
}

/// A registered attestor: an institution that countersigns event digests.
/// The secp256k1 public key (33-byte compressed, hex) verifies signatures
/// over the raw 32-byte event digest.
#[cw_serde]
pub struct AttestorRecord {
    pub addr: Addr,
    pub class: AttestorClass,
    pub name: String,
    pub pubkey_hex: String,
    pub active: bool,
    pub registered_at: u64,
}

/// One verified countersignature recorded on an event, with the class the
/// attestor held AT SIGNING TIME (roster changes never rewrite history).
#[cw_serde]
pub struct RecordedAttestation {
    pub attestor: Addr,
    pub class_at_signing: AttestorClass,
    pub signature_hex: String,
}

/// One append-only register event. `id` is the client-supplied idempotency
/// key (the app-server saga re-drives on crash; a duplicate id is rejected,
/// which the sweeper reads as already-anchored).
#[cw_serde]
pub struct RegisterEvent {
    pub id: String,
    pub seq: u64,            // contract-assigned global monotonic sequence
    pub instrument_seq: u64, // contract-assigned per-instrument sequence
    pub instrument_ref: String, // opaque instrument reference (digest-derived; never a name)
    pub event_type: String,  // catalogue type, e.g. INSTRUMENT_ISSUED, ATTEMPT_CLOSED
    pub digest: String,      // sha256 hex of the canonical event preimage (held off-chain)
    pub reason_code: Option<String>, // taxonomy code for outcome events
    pub dsvs_doc_id: Option<String>, // link to the x/dsvs document where signatures live
    pub attestations: Vec<RecordedAttestation>,
    pub submitted_by: Addr,
    pub created_at: u64, // block time, unix seconds
}

pub const CONFIG: Item<Config> = Item::new("config");

// Events: by id, with global and per-instrument sequence indexes.
pub const EVENTS: Map<String, RegisterEvent> = Map::new("events"); // id -> event
pub const BY_SEQ: Map<u64, String> = Map::new("by_seq"); // seq -> id
pub const BY_INSTRUMENT: Map<(String, u64), String> = Map::new("by_instrument"); // (instrument_ref, instrument_seq) -> id
pub const EVENT_COUNT: Item<u64> = Item::new("event_count");
pub const INSTRUMENT_COUNT: Map<String, u64> = Map::new("instrument_count"); // instrument_ref -> per-instrument counter

// Attestor roster. Changes are themselves recorded as events by the caller.
pub const ATTESTORS: Map<Addr, AttestorRecord> = Map::new("attestors");

// Holdership: exactly one holder per instrument (BRD FR-902). Compare-and-set
// via SetHolder prevents double assignment; execution redirect is a later
// phase, but the slot exists from day one so the register never migrates.
pub const HOLDER: Map<String, String> = Map::new("holder"); // instrument_ref -> holder ref

// Authorized writers: wallets besides the operator that may append events and set holders. The
// app-server signs from a POOL of wallets (the orchestrator, its credential wallet and its
// ephemeral signers) to parallelise, so "operator only" would refuse most of its writes; the
// operator authorizes the pool instead (SetWriters, or MigrateMsg.writers on upgrade).
pub const WRITERS: Map<Addr, bool> = Map::new("writers");
