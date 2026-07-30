use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Uint128, Addr};
use crate::state::{GAA, PAP, SARO, NCA, Obligation, DisbursementVoucher, Disbursement, TokenInfo, ProcurementContract, PhilGEPSState, DPWHContract, DPWHComponent, DPWHBidder, DPWHCoordinate, DPWHState};
use cw20::Cw20Coin;

#[cw_serde]
pub struct InstantiateMsg {
    pub count: i32,
}

// DPWH nested message types for contract creation
#[cw_serde]
pub struct DPWHComponentMsg {
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

#[cw_serde]
pub struct DPWHBidderMsg {
    pub name: Option<String>,
    pub pcab_id: Option<String>,
    pub participation: Option<u32>,
    pub is_winner: Option<bool>,
}

#[cw_serde]
pub struct DPWHCoordinateMsg {
    pub component_id: Option<String>,
    pub description: Option<String>,
    pub latitude: Option<String>,
    pub longitude: Option<String>,
    pub source: Option<String>,
    pub location_verified: Option<bool>,
}

#[cw_serde]
pub enum ExecuteMsg {
    // Legacy counter functions
    Increment {},
    Reset { count: i32 },
    
    // Budget hierarchy functions
    CreateGAA {
        id: String,
        year: u32,
        total_amount: Uint128,
        status: String,
        token_name: String,    // e.g., "GAA 2025 Peso"
        token_symbol: String,  // e.g., "GAA2025PESO"
        token_decimals: u8,    // e.g., 6 for peso cents
        cw20_code_id: u64,     // CW20 contract code ID
    },
    CreatePAP {
        id: String,
        gaa_id: String,
        // UACS and Budget Classification Fields (from backend)
        sorder: Option<u32>,
        department: Option<String>,
        uacs_dpt_dsc: Option<String>,
        agency: Option<String>,
        uacs_agy_dsc: Option<String>,
        prexc_fpap_id: Option<String>,
        prexc_level: Option<String>,
        dsc: Option<String>,
        oper_unit: Option<String>,
        uacs_oper_dsc: Option<String>,
        uacs_reg_id: Option<String>,
        uacs_operdiv_id: Option<String>,
        uacs_div_dsc: Option<String>,
        fund_cd: Option<String>,
        uacs_fundsubcat_dsc: Option<String>,
        uacs_exp_cd: Option<String>,
        uacs_exp_dsc: Option<String>,
        uacs_sobj_cd: Option<String>,
        uacs_sobj_dsc: String,
        amount: Uint128,
    },
    CreateSARO {
        id: String,
        pap_id: String,
        saro_number: String,
        amount: Uint128,
        release_date: Option<String>,
        department: Option<String>,
        agency: Option<String>,
        operating_unit: Option<String>,
        purpose: Option<String>,
    },
    CreateObligation {
        id: String,
        saro_id: String,  // Changed from nca_id to saro_id
        obligation_number: String,
        amount: Uint128,
        description: Option<String>,
        payee: Option<String>,
        obligation_date: Option<u64>,  // Unix timestamp
    },
    CreateNCA {
        id: String,
        saro_ids: Vec<String>,  // NCA can be a child of multiple SAROs
        nca_number: String,
        amount: Uint128,
        approved_date: Option<u64>,  // Unix timestamp
        issue_date: Option<u64>,     // Unix timestamp
        release_date: Option<u64>,   // Unix timestamp
        department: Option<String>,
        agency: Option<String>,
        operating_unit: Option<String>,
        purpose: Option<String>,
        cancel_remarks: Option<String>,
        release_type_cd: Option<String>,
    },
    CreateDisbursementVoucher {
        id: String,
        obligation_id: String,  // DV requires an Obligation
        nca_id: String,         // DV requires an NCA
        dv_number: String,
        amount: Uint128,
        description: Option<String>,
        payee: Option<String>,
        disbursement_voucher_date: Option<u64>,  // Unix timestamp
    },
    CreateDisbursement {
        id: String,
        disbursement_voucher_id: String,
        disbursement_number: String,
        amount: Uint128,
        recipient_qadena_address: String, // Recipient address for token transfer
        disbursement_date: u64,
        description: Option<String>,
        payee: Option<String>,
        payment_method: Option<String>,
        reference_number: Option<String>,
        status: Option<String>,
    },
    
    // PhilGEPS Procurement Contract functions
    CreateProcurementContract {
        id: String,
        reference_id: Option<String>,
        contract_no: Option<String>,
        award_title: Option<String>,
        notice_title: Option<String>,
        awardee_name: Option<String>,
        organization_name: Option<String>,
        area_of_delivery: Option<String>,
        business_category: Option<String>,
        contract_amount: Uint128,
        award_date: Option<String>,
        award_status: Option<String>,
    },
    DeleteProcurementContract {
        id: String,
    },
    
    // DPWH Contract functions
    CreateDPWHContract {
        contract_id: String,
        description: Option<String>,
        category: Option<String>,
        status: Option<String>,
        budget: Option<Uint128>,
        amount_paid: Option<Uint128>,
        progress: Option<u32>,
        region: Option<String>,
        province: Option<String>,
        infra_type: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
        verified: Option<bool>,
        infra_type_1: Option<String>,
        contractor: Option<String>,
        start_date: Option<u64>,
        completion_date: Option<u64>,
        infra_year: Option<String>,
        contract_effectivity_date: Option<u64>,
        expiry_date: Option<u64>,
        program_name: Option<String>,
        source_of_funds: Option<String>,
        contract_name: Option<String>,
        award_amount: Option<String>,
        // Nested data
        components: Option<Vec<DPWHComponentMsg>>,
        bidders: Option<Vec<DPWHBidderMsg>>,
        coordinates: Option<Vec<DPWHCoordinateMsg>>,
    },
    UpdateDPWHContract {
        contract_id: String,
        description: Option<String>,
        category: Option<String>,
        status: Option<String>,
        budget: Option<Uint128>,
        amount_paid: Option<Uint128>,
        progress: Option<u32>,
        region: Option<String>,
        province: Option<String>,
        infra_type: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
        verified: Option<bool>,
        contractor: Option<String>,
        infra_year: Option<String>,
        program_name: Option<String>,
        source_of_funds: Option<String>,
    },
    DeleteDPWHContract {
        contract_id: String,
    },
    AddDPWHComponent {
        contract_id: String,
        component_id: Option<String>,
        description: Option<String>,
        infra_type: Option<String>,
        type_of_work: Option<String>,
        region: Option<String>,
        province: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
        coordinate_source: Option<String>,
        location_verified: Option<bool>,
    },
    AddDPWHBidder {
        contract_id: String,
        name: Option<String>,
        pcab_id: Option<String>,
        participation: Option<u32>,
        is_winner: Option<bool>,
    },
    AddDPWHCoordinate {
        contract_id: String,
        component_id: Option<String>,
        description: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
        source: Option<String>,
        location_verified: Option<bool>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // Legacy counter query
    #[returns(GetCountResponse)]
    GetCount {},
    
    // Budget hierarchy queries
    #[returns(GAA)]
    GetGAA { id: String },
    #[returns(PaginatedGAAsResponse)]
    GetGAAs { 
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(PaginatedGAAsResponse)]
    GetGAAByYear {
        year: u32,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(PAP)]
    GetPAP { 
        gaa_id: String,
        pap_id: String,
    },
    #[returns(PaginatedPAPsResponse)]
    GetPAPsByGAA { 
        gaa_id: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(PaginatedPAPsResponse)]
    GetPAPsByGAANumIdx { 
        gaa_id: String,
        start_idx: Option<u32>,  // Numeric index to start from (inclusive)
        limit: Option<u32>,
    },
    #[returns(PAP)]
    GetPAPByCompositeKey {
        composite_key_hash: String,  // SHA256 hash of: year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
    },
    #[returns(SARO)]
    GetSARO { 
        pap_id: String,
        saro_id: String,
    },
    #[returns(PaginatedSAROsResponse)]
    GetSAROsByPAP { 
        pap_id: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(Obligation)]
    GetObligation { 
        saro_id: String,
        obligation_id: String,
    },
    #[returns(PaginatedObligationsResponse)]
    GetObligationsBySARO { 
        saro_id: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(NCA)]
    GetNCA { 
        nca_id: String,
    },
    #[returns(PaginatedNCAsResponse)]
    GetNCAsBySARO { 
        saro_id: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(DisbursementVoucher)]
    GetDisbursementVoucher { 
        obligation_id: String,
        nca_id: String,
        dv_id: String,
    },
    #[returns(PaginatedDisbursementVouchersResponse)]
    GetDisbursementVouchersByObligation { 
        obligation_id: String,
        start_after: Option<(String, String)>,  // (nca_id, dv_id)
        limit: Option<u32>,
    },
    #[returns(PaginatedDisbursementVouchersResponse)]
    GetDisbursementVouchersByNCA { 
        nca_id: String,
        start_after: Option<(String, String)>,  // (obligation_id, dv_id)
        limit: Option<u32>,
    },
    #[returns(Disbursement)]
    GetDisbursement { 
        dv_id: String,
        disbursement_id: String,
    },
    #[returns(PaginatedDisbursementsResponse)]
    GetDisbursementsByDV { 
        dv_id: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(BudgetHierarchyResponse)]
    GetBudgetHierarchy { 
        gaa_id: String,
        pap_start_after: Option<String>,  // Cursor-based pagination (efficient)
        paps_per_page: Option<u32>,
        saros_per_pap: Option<u32>,
        ncas_per_saro: Option<u32>,
        obligations_per_saro: Option<u32>,
        dvs_per_parent: Option<u32>,
        disbursements_per_dv: Option<u32>,
    },
    #[returns(TokenInfo)]
    GetTokenInfo { gaa_id: String },
    #[returns(Uint128)]
    GetTokenBalance { gaa_id: String, address: String },
    
    // PhilGEPS queries
    #[returns(ProcurementContract)]
    GetProcurementContract { id: String },
    #[returns(PaginatedProcurementContractsResponse)]
    GetProcurementContracts {
        start_after: Option<String>,
        limit: Option<u32>,
        organization_name: Option<String>,
        awardee_name: Option<String>,
        business_category: Option<String>,
    },
    #[returns(PaginatedProcurementContractsResponse)]
    GetProcurementContractsByNumIdx {
        start_idx: Option<u32>,  // Numeric index to start from (inclusive)
        limit: Option<u32>,
    },
    #[returns(PhilGEPSState)]
    GetPhilGEPSState {},
    #[returns(ProcurementContract)]
    GetProcurementContractByReferenceId { reference_id: String },
    #[returns(ProcurementContract)]
    GetProcurementContractByContractNo { contract_no: String },
    
    // DPWH queries
    #[returns(DPWHContract)]
    GetDPWHContract { contract_id: String },
    #[returns(PaginatedDPWHContractsResponse)]
    GetDPWHContracts {
        start_after: Option<String>,
        limit: Option<u32>,
        region: Option<String>,
        status: Option<String>,
        infra_year: Option<String>,
    },
    #[returns(PaginatedDPWHContractsResponse)]
    GetDPWHContractsByNumIdx {
        start_idx: Option<u32>,  // Numeric index to start from (inclusive)
        limit: Option<u32>,
    },
    #[returns(PaginatedDPWHContractsResponse)]
    GetDPWHContractsByRegion {
        region: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(PaginatedDPWHContractsResponse)]
    GetDPWHContractsByStatus {
        status: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(PaginatedDPWHContractsResponse)]
    GetDPWHContractsByYear {
        infra_year: String,
        start_after: Option<String>,
        limit: Option<u32>,
    },
    #[returns(DPWHState)]
    GetDPWHState {},
    #[returns(DPWHContractWithChildren)]
    GetDPWHContractFull { contract_id: String },
    #[returns(Vec<DPWHComponent>)]
    GetDPWHComponents { contract_id: String },
    #[returns(Vec<DPWHBidder>)]
    GetDPWHBidders { contract_id: String },
    #[returns(Vec<DPWHCoordinate>)]
    GetDPWHCoordinates { contract_id: String },
}

// Response structures
#[cw_serde]
pub struct GetCountResponse {
    pub count: i32,
}

#[cw_serde]
pub struct BudgetHierarchyResponse {
    pub gaa: GAA,
    pub paps: Vec<PAPWithChildren>,
    pub total_paps: u32,  // Total number of PAPs for this GAA
}

#[cw_serde]
pub struct PAPWithChildren {
    pub pap: PAP,
    pub saros: Vec<SAROWithChildren>,
}

#[cw_serde]
pub struct SAROWithChildren {
    pub saro: SARO,
    pub obligations: Vec<ObligationWithChildren>,  // Obligations with their DVs
    pub ncas: Vec<NCAWithChildren>,  // NCAs with their DVs
}

#[cw_serde]
pub struct ObligationWithChildren {
    pub obligation: Obligation,
    pub disbursement_vouchers: Vec<DisbursementVoucher>,
}

#[cw_serde]
pub struct NCAWithChildren {
    pub nca: NCA,
    pub disbursement_vouchers: Vec<DisbursementVoucher>,
}

// Paginated response structures with total counts
#[cw_serde]
pub struct PaginatedGAAsResponse {
    pub gaas: Vec<GAA>,
    pub total: u32,
    pub count: u32,      // Number of items in this response
    pub has_more: bool,  // True if there are more items after this page
}

#[cw_serde]
pub struct PaginatedPAPsResponse {
    pub paps: Vec<PAP>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedSAROsResponse {
    pub saros: Vec<SARO>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedObligationsResponse {
    pub obligations: Vec<Obligation>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedNCAsResponse {
    pub ncas: Vec<NCA>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedDisbursementVouchersResponse {
    pub disbursement_vouchers: Vec<DisbursementVoucher>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedDisbursementsResponse {
    pub disbursements: Vec<Disbursement>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct PaginatedProcurementContractsResponse {
    pub contracts: Vec<ProcurementContract>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

// DPWH Response structures
#[cw_serde]
pub struct PaginatedDPWHContractsResponse {
    pub contracts: Vec<DPWHContract>,
    pub total: u32,
    pub count: u32,
    pub has_more: bool,
}

#[cw_serde]
pub struct DPWHContractWithChildren {
    pub contract: DPWHContract,
    pub components: Vec<DPWHComponent>,
    pub bidders: Vec<DPWHBidder>,
    pub coordinates: Vec<DPWHCoordinate>,
}
