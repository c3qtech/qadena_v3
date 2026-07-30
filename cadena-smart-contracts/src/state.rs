use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};
use cw20::Cw20Coin;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct State {
    pub count: i32,
    pub owner: Addr,
}

// Budget hierarchy structures
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct GAA {
    pub id: String,
    pub year: u32,
    pub total_amount: Uint128,
    pub description: Option<String>, // From backend
    pub available_amount_for_paps: Uint128, // Remaining unallocated amount (blockchain-specific)
    pub token_address: Option<Addr>, // CW20 token contract address (blockchain-specific)
    pub status: String, // active, closed
    pub pap_count: u32, // Cached count of PAPs for efficient queries (blockchain-specific)
    
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct PAP {
    pub id: String,
    pub gaa_id: String,
    pub idx: u32, // Auto-assigned index within GAA (blockchain-specific)
    
    // UACS and Budget Classification Fields (from backend)
    pub sorder: Option<u32>, // SORDER - Sort order
    pub department: Option<String>, // DEPARTMENT - Department code
    pub uacs_dpt_dsc: Option<String>, // UACS_DPT_DSC - Department description
    pub agency: Option<String>, // AGENCY - Agency code
    pub uacs_agy_dsc: Option<String>, // UACS_AGY_DSC - Agency description
    pub prexc_fpap_id: Option<String>, // PREXC_FPAP_ID - Program/Project ID
    pub prexc_level: Option<String>, // PREXC_LEVEL - Program level
    pub dsc: Option<String>, // DSC - Description
    pub oper_unit: Option<String>, // OPERUNIT - Operating unit
    pub uacs_oper_dsc: Option<String>, // UACS_OPER_DSC - Operating unit description
    pub uacs_reg_id: Option<String>, // UACS_REG_ID - Region ID
    pub uacs_operdiv_id: Option<String>, // UACS_OPERDIV_ID - Operating division ID
    pub uacs_div_dsc: Option<String>, // UACS_DIV_DSC - Division description
    pub fund_cd: Option<String>, // FUNDCD - Fund code
    pub uacs_fundsubcat_dsc: Option<String>, // UACS_FUNDSUBCAT_DSC - Fund subcategory description
    pub uacs_exp_cd: Option<String>, // UACS_EXP_CD - Expense code
    pub uacs_exp_dsc: Option<String>, // UACS_EXP_DSC - Expense description
    pub uacs_sobj_cd: Option<String>, // UACS_SOBJ_CD - Sub-object code
    pub uacs_sobj_dsc: String, // UACS_SOBJ_DSC - Sub-object description (kept for compatibility)
    pub amt: Uint128, // AMT - Amount (from backend)
    pub available_amount_for_saros: Uint128, // Remaining unallocated amount (blockchain-specific)
    
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct SARO {
    pub id: String,
    pub pap_id: String,
    pub saro_number: String,
    pub amount: Uint128,
    pub release_date: Option<u64>, // From backend (timestamp)
    pub department: Option<String>, // From backend
    pub agency: Option<String>,
    pub operating_unit: Option<String>,
    pub purpose: Option<String>,
    
    // Blockchain-specific fields
    pub available_amount_for_obligations: Uint128, // Available amount for creating Obligations
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct NCA {
    pub id: String,
    pub saro_ids: Vec<String>,  // NCA can be a child of multiple SAROs
    pub nca_number: String,
    pub amount: Uint128,
    pub approved_date: Option<u64>, // From backend (timestamp)
    pub issue_date: Option<u64>, // From backend (timestamp)
    pub release_date: Option<u64>, // From backend (timestamp)
    pub department: Option<String>, // From backend
    pub agency: Option<String>,
    pub operating_unit: Option<String>,
    pub purpose: Option<String>,
    pub cancel_remarks: Option<String>, // From backend
    pub release_type_cd: Option<String>, // From backend

    pub liquidated_amount_from_disbursements: Uint128, // Available amount for Disbursements (blockchain-specific)
    
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Obligation {
    pub id: String,
    pub saro_id: String,  // Obligation is a child of SARO
    pub obligation_number: String,
    pub amount: Uint128,
    pub liquidated_amount_from_disbursements: Uint128, // liquidated amount from DisbursementVouchers (blockchain-specific)
    pub available_amount_for_disbursement_vouchers: Uint128, // Available amount for Disbursements (blockchain-specific)
    pub department: Option<String>, // From backend
    pub purpose: Option<String>, // From backend
    pub obligation_date: Option<u64>, // From backend (timestamp)
    pub status: Option<String>, // From backend (pending, approved, disbursed)
    
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DisbursementVoucher {
    pub id: String,
    pub nca_id: String, // From backend (order matches backend)
    pub obligation_id: String, // From backend
    pub dv_number: String,
    pub amount: Uint128,
    pub liquidated_amount_from_disbursements: Uint128, // liquidated amount from Disbursements (blockchain-specific)
    pub description: Option<String>,
    pub payee: Option<String>,
    pub voucher_date: Option<u64>, // From backend (timestamp)
    pub status: Option<String>, // From backend (pending, approved, disbursed)
    
    pub created_by: Addr, // blockchain-specific
    pub created_at: u64, // blockchain-specific
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct Disbursement {
    pub id: String,
    pub dv_id: String,          // Reference to the DisbursementVoucher
    pub recipient: Addr,        // Who received the disbursement
    pub amount: Uint128,        // Amount disbursed
    pub transaction_hash: Option<String>, // Optional transaction reference
    pub disbursement_date: u64, // Timestamp of disbursement

    pub created_by: Addr,       // Who initiated the disbursement
    pub created_at: u64,        // Creation timestamp
}

// Storage with composite keys for efficient pagination
// Format: Map<(parent_id, child_id), Entity>
pub const STATE: Item<State> = Item::new("state");
pub const GAAS: Map<String, GAA> = Map::new("gaas"); // No parent, single key
pub const GAAS_BY_YEAR: Map<(u32, String), ()> = Map::new("gaas_by_year"); // (year, gaa_id) -> () for year-based queries
pub const PAPS: Map<(String, String), PAP> = Map::new("paps"); // (gaa_id, pap_id)
pub const PAPS_BY_IDX: Map<(String, u32), String> = Map::new("paps_by_idx"); // (gaa_id, idx) -> pap_id
pub const PAPS_BY_COMPOSITE_KEY: Map<String, String> = Map::new("paps_by_composite_key"); // composite_key_hash -> pap_id
pub const SAROS: Map<(String, String), SARO> = Map::new("saros"); // (pap_id, saro_id)
pub const OBLIGATIONS: Map<(String, String), Obligation> = Map::new("obligations"); // (saro_id, obligation_id)
// NCAs now have multiple SARO parents, so we store them canonically by ID
// and maintain a separate index for (saro_id, nca_id) lookups.
pub const NCAS_BY_ID: Map<String, NCA> = Map::new("ncas_by_id"); // (nca_id)
pub const NCAS_BY_SARO: Map<(String, String), ()> = Map::new("ncas_by_saro"); // (saro_id, nca_id)
pub const DISBURSEMENT_VOUCHERS: Map<(String, String, String), DisbursementVoucher> = Map::new("disbursement_vouchers"); // (obligation_id, nca_id, dv_id)
pub const DISBURSEMENTS: Map<(String, String), Disbursement> = Map::new("disbursements"); // (dv_id, disbursement_id)

// Note: Index maps are no longer needed with composite keys!
// Pagination is handled via prefix() queries on the composite key maps

// PhilGEPS global state for efficient queries
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct PhilGEPSState {
    pub contract_count: u32,  // Total number of contracts for efficient pagination
}

// PhilGEPS Procurement Contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct ProcurementContract {
    pub id: String,
    pub idx: u32,  // Auto-assigned index for efficient numeric pagination (blockchain-specific)
    pub reference_id: Option<String>,
    pub contract_no: Option<String>,
    pub award_title: Option<String>,
    pub notice_title: Option<String>,
    pub awardee_name: Option<String>,
    pub organization_name: Option<String>,
    pub area_of_delivery: Option<String>,
    pub business_category: Option<String>,
    pub contract_amount: Uint128,  // In centavos
    pub award_date: Option<String>,
    pub award_status: Option<String>,
    
    pub created_by: Addr,
    pub created_at: u64,
}

// PhilGEPS storage
pub const PHILGEPS_STATE: Item<PhilGEPSState> = Item::new("philgeps_state");
pub const PHILGEPS_CONTRACTS: Map<String, ProcurementContract> = Map::new("philgeps_contracts");
pub const PHILGEPS_CONTRACTS_BY_IDX: Map<u32, String> = Map::new("philgeps_contracts_by_idx"); // idx -> contract_id
pub const PHILGEPS_CONTRACTS_BY_REF_ID: Map<String, String> = Map::new("philgeps_by_ref_id"); // reference_id -> contract_id
pub const PHILGEPS_CONTRACTS_BY_CONTRACT_NO: Map<String, String> = Map::new("philgeps_by_contract_no"); // contract_no -> contract_id

// DPWH global state for efficient queries
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DPWHState {
    pub contract_count: u32,  // Total number of contracts for efficient pagination
}

// DPWH Contract
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DPWHContract {
    pub contract_id: String,
    pub idx: u32,  // Auto-assigned index for efficient numeric pagination (blockchain-specific)
    pub description: Option<String>,
    pub category: Option<String>,
    pub status: Option<String>,
    pub budget: Option<Uint128>,  // In centavos
    pub amount_paid: Option<Uint128>,
    pub progress: Option<u32>,  // Progress percentage (0-100)
    pub region: Option<String>,
    pub province: Option<String>,
    pub infra_type: Option<String>,
    pub latitude: Option<String>,  // Stored as string for precision
    pub longitude: Option<String>,
    pub verified: Option<bool>,
    pub infra_type_1: Option<String>,
    pub contractor: Option<String>,
    pub start_date: Option<u64>,  // Unix timestamp
    pub completion_date: Option<u64>,
    pub infra_year: Option<String>,
    pub contract_effectivity_date: Option<u64>,
    pub expiry_date: Option<u64>,
    pub program_name: Option<String>,
    pub source_of_funds: Option<String>,
    pub contract_name: Option<String>,
    pub award_amount: Option<String>,
    
    pub created_by: Addr,
    pub created_at: u64,
}

// DPWH Component (child of DPWHContract)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DPWHComponent {
    pub contract_id: String,
    pub idx: u32,
    pub component_id: Option<String>,
    pub description: Option<String>,
    pub infra_type: Option<String>,
    pub type_of_work: Option<String>,
    pub region: Option<String>,
    pub province: Option<String>,
    pub latitude: Option<String>,
    pub longitude: Option<String>,
    pub coordinate_source: Option<String>,
    pub location_verified: Option<bool>,
}

// DPWH Bidder (child of DPWHContract)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DPWHBidder {
    pub contract_id: String,
    pub idx: u32,
    pub name: Option<String>,
    pub pcab_id: Option<String>,
    pub participation: Option<u32>,  // Percentage (0-100)
    pub is_winner: Option<bool>,
}

// DPWH Coordinate (child of DPWHContract)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DPWHCoordinate {
    pub contract_id: String,
    pub idx: u32,
    pub component_id: Option<String>,
    pub description: Option<String>,
    pub latitude: Option<String>,
    pub longitude: Option<String>,
    pub source: Option<String>,
    pub location_verified: Option<bool>,
}

// DPWH storage
pub const DPWH_STATE: Item<DPWHState> = Item::new("dpwh_state");
pub const DPWH_CONTRACTS: Map<String, DPWHContract> = Map::new("dpwh_contracts");
pub const DPWH_CONTRACTS_BY_IDX: Map<u32, String> = Map::new("dpwh_contracts_by_idx"); // idx -> contract_id
pub const DPWH_CONTRACTS_BY_REGION: Map<(String, String), ()> = Map::new("dpwh_by_region"); // (region, contract_id)
pub const DPWH_CONTRACTS_BY_STATUS: Map<(String, String), ()> = Map::new("dpwh_by_status"); // (status, contract_id)
pub const DPWH_CONTRACTS_BY_YEAR: Map<(String, String), ()> = Map::new("dpwh_by_year"); // (infra_year, contract_id)
pub const DPWH_COMPONENTS: Map<(String, u32), DPWHComponent> = Map::new("dpwh_components"); // (contract_id, idx)
pub const DPWH_BIDDERS: Map<(String, u32), DPWHBidder> = Map::new("dpwh_bidders"); // (contract_id, idx)
pub const DPWH_COORDINATES: Map<(String, u32), DPWHCoordinate> = Map::new("dpwh_coordinates"); // (contract_id, idx)

// Token management
pub const TOKEN_INFO: Map<String, TokenInfo> = Map::new("token_info");

// Temporary storage for tracking GAA creation during token instantiation
pub const PENDING_GAA: Item<String> = Item::new("pending_gaa");

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct TokenInfo {
    pub gaa_id: String,
    pub token_address: Addr,
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
    pub total_supply: Uint128,
}
