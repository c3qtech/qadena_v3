#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, SubMsg, WasmMsg, CosmosMsg, Uint128, Reply, SubMsgResult, Order};
use cw_storage_plus::Bound;
use cw2::set_contract_version;
use serde_json::json;
use cw20::{Cw20ExecuteMsg, Cw20QueryMsg, BalanceResponse};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, GetCountResponse, InstantiateMsg, QueryMsg, BudgetHierarchyResponse, PAPWithChildren, SAROWithChildren, ObligationWithChildren, NCAWithChildren, PaginatedGAAsResponse, PaginatedPAPsResponse, PaginatedSAROsResponse, PaginatedObligationsResponse, PaginatedNCAsResponse, PaginatedDisbursementVouchersResponse, PaginatedDisbursementsResponse, PaginatedProcurementContractsResponse, PaginatedDPWHContractsResponse, DPWHContractWithChildren, DPWHComponentMsg, DPWHBidderMsg, DPWHCoordinateMsg};
use crate::state::{State, STATE, GAA, PAP, SARO, NCA, Obligation, DisbursementVoucher, Disbursement, GAAS, GAAS_BY_YEAR, PAPS, PAPS_BY_IDX, PAPS_BY_COMPOSITE_KEY, SAROS, NCAS_BY_ID, NCAS_BY_SARO, OBLIGATIONS, DISBURSEMENT_VOUCHERS, DISBURSEMENTS, TokenInfo, TOKEN_INFO, PENDING_GAA, ProcurementContract, PhilGEPSState, PHILGEPS_STATE, PHILGEPS_CONTRACTS, PHILGEPS_CONTRACTS_BY_IDX, PHILGEPS_CONTRACTS_BY_REF_ID, PHILGEPS_CONTRACTS_BY_CONTRACT_NO, DPWHContract, DPWHComponent, DPWHBidder, DPWHCoordinate, DPWHState, DPWH_STATE, DPWH_CONTRACTS, DPWH_CONTRACTS_BY_IDX, DPWH_CONTRACTS_BY_REGION, DPWH_CONTRACTS_BY_STATUS, DPWH_CONTRACTS_BY_YEAR, DPWH_COMPONENTS, DPWH_BIDDERS, DPWH_COORDINATES};
use sha2::{Sha256, Digest};

// Helper function to compute PAP composite key hash
// Composite key: year|department|agency|prexc_fpap_id|operunit|fundcd|uacs_sobj_cd|uacs_reg_id
fn compute_pap_composite_key_hash(
    year: u32,
    department: &Option<String>,
    agency: &Option<String>,
    prexc_fpap_id: &Option<String>,
    oper_unit: &Option<String>,
    fund_cd: &Option<String>,
    uacs_sobj_cd: &Option<String>,
    uacs_reg_id: &Option<String>,
) -> String {
    let composite_key = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        year,
        department.as_deref().unwrap_or(""),
        agency.as_deref().unwrap_or(""),
        prexc_fpap_id.as_deref().unwrap_or(""),
        oper_unit.as_deref().unwrap_or(""),
        fund_cd.as_deref().unwrap_or(""),
        uacs_sobj_cd.as_deref().unwrap_or(""),
        uacs_reg_id.as_deref().unwrap_or(""),
    );
    
    let mut hasher = Sha256::new();
    hasher.update(composite_key.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

// Helper function to convert year to Roman numeral
fn year_to_roman(year: u32) -> String {
    let last_two_digits = year % 100;
    match last_two_digits {
        20 => "XX".to_string(),
        21 => "XXI".to_string(),
        22 => "XXII".to_string(),
        23 => "XXIII".to_string(),
        24 => "XXIV".to_string(),
        25 => "XXV".to_string(),
        26 => "XXVI".to_string(),
        27 => "XXVII".to_string(),
        28 => "XXVIII".to_string(),
        29 => "XXIX".to_string(),
        30 => "XXX".to_string(),
        _ => format!("{}", last_two_digits), // Fallback to number
    }
}

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cadena";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        count: msg.count,
        owner: info.sender.clone(),
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("count", msg.count.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Increment {} => execute::increment(deps),
        ExecuteMsg::Reset { count } => execute::reset(deps, info, count),
        ExecuteMsg::CreateGAA { id, year, total_amount, status, token_name, token_symbol, token_decimals, cw20_code_id } => {
            execute::create_gaa(deps, env, info, id, year, total_amount, status, token_name, token_symbol, token_decimals, cw20_code_id)
        },
        ExecuteMsg::CreatePAP {
            id,
            gaa_id,
            sorder,
            department,
            uacs_dpt_dsc,
            agency,
            uacs_agy_dsc,
            prexc_fpap_id,
            prexc_level,
            dsc,
            oper_unit,
            uacs_oper_dsc,
            uacs_reg_id,
            uacs_operdiv_id,
            uacs_div_dsc,
            fund_cd,
            uacs_fundsubcat_dsc,
            uacs_exp_cd,
            uacs_exp_dsc,
            uacs_sobj_cd,
            uacs_sobj_dsc,
            amount,
        } => {
            execute::create_pap(
                deps,
                env,
                info,
                id,
                gaa_id,
                sorder,
                department,
                uacs_dpt_dsc,
                agency,
                uacs_agy_dsc,
                prexc_fpap_id,
                prexc_level,
                dsc,
                oper_unit,
                uacs_oper_dsc,
                uacs_reg_id,
                uacs_operdiv_id,
                uacs_div_dsc,
                fund_cd,
                uacs_fundsubcat_dsc,
                uacs_exp_cd,
                uacs_exp_dsc,
                uacs_sobj_cd,
                uacs_sobj_dsc,
                amount,
            )
        },
        ExecuteMsg::CreateSARO { id, pap_id, saro_number, amount, release_date, department, agency, operating_unit, purpose } => {
            execute::create_saro(deps, env, info, id, pap_id, saro_number, amount, release_date, department, agency, operating_unit, purpose)
        },
        ExecuteMsg::CreateObligation { id, saro_id, obligation_number, amount, description, payee, obligation_date } => {
            execute::create_obligation(deps, env, info, id, saro_id, obligation_number, amount, description, payee, obligation_date)
        },
        ExecuteMsg::CreateNCA { id, saro_ids, nca_number, amount, approved_date, issue_date, release_date, department, agency, operating_unit, purpose, cancel_remarks, release_type_cd } => {
            execute::create_nca(deps, env, info, id, saro_ids, nca_number, amount, approved_date, issue_date, release_date, department, agency, operating_unit, purpose, cancel_remarks, release_type_cd)
        },
        ExecuteMsg::CreateDisbursementVoucher { id, obligation_id, nca_id, dv_number, amount, description, payee, disbursement_voucher_date } => {
            execute::create_disbursement_voucher(deps, env, info, id, obligation_id, nca_id, dv_number, amount, description, payee, disbursement_voucher_date)
        },
        ExecuteMsg::CreateDisbursement { id, disbursement_voucher_id, disbursement_number, amount, recipient_qadena_address, disbursement_date, description, payee, payment_method, reference_number, status } => {
            execute::create_disbursement(deps, env, info, id, disbursement_voucher_id, disbursement_number, amount, recipient_qadena_address, disbursement_date, description, payee, payment_method, reference_number, status)
        },
        ExecuteMsg::CreateProcurementContract { id, reference_id, contract_no, award_title, notice_title, awardee_name, organization_name, area_of_delivery, business_category, contract_amount, award_date, award_status } => {
            execute::create_procurement_contract(deps, env, info, id, reference_id, contract_no, award_title, notice_title, awardee_name, organization_name, area_of_delivery, business_category, contract_amount, award_date, award_status)
        },
        ExecuteMsg::DeleteProcurementContract { id } => {
            execute::delete_procurement_contract(deps, info, id)
        },
        ExecuteMsg::CreateDPWHContract { 
            contract_id, description, category, status, budget, amount_paid, progress,
            region, province, infra_type, latitude, longitude, verified, infra_type_1,
            contractor, start_date, completion_date, infra_year, contract_effectivity_date,
            expiry_date, program_name, source_of_funds, contract_name, award_amount,
            components, bidders, coordinates
        } => {
            execute::create_dpwh_contract(
                deps, env, info, contract_id, description, category, status, budget, amount_paid,
                progress, region, province, infra_type, latitude, longitude, verified, infra_type_1,
                contractor, start_date, completion_date, infra_year, contract_effectivity_date,
                expiry_date, program_name, source_of_funds, contract_name, award_amount,
                components, bidders, coordinates
            )
        },
        ExecuteMsg::UpdateDPWHContract {
            contract_id, description, category, status, budget, amount_paid, progress,
            region, province, infra_type, latitude, longitude, verified, contractor,
            infra_year, program_name, source_of_funds
        } => {
            execute::update_dpwh_contract(
                deps, info, contract_id, description, category, status, budget, amount_paid,
                progress, region, province, infra_type, latitude, longitude, verified,
                contractor, infra_year, program_name, source_of_funds
            )
        },
        ExecuteMsg::DeleteDPWHContract { contract_id } => {
            execute::delete_dpwh_contract(deps, info, contract_id)
        },
        ExecuteMsg::AddDPWHComponent {
            contract_id, component_id, description, infra_type, type_of_work,
            region, province, latitude, longitude, coordinate_source, location_verified
        } => {
            execute::add_dpwh_component(
                deps, info, contract_id, component_id, description, infra_type, type_of_work,
                region, province, latitude, longitude, coordinate_source, location_verified
            )
        },
        ExecuteMsg::AddDPWHBidder { contract_id, name, pcab_id, participation, is_winner } => {
            execute::add_dpwh_bidder(deps, info, contract_id, name, pcab_id, participation, is_winner)
        },
        ExecuteMsg::AddDPWHCoordinate {
            contract_id, component_id, description, latitude, longitude, source, location_verified
        } => {
            execute::add_dpwh_coordinate(
                deps, info, contract_id, component_id, description, latitude, longitude, source, location_verified
            )
        },
    }
}

pub mod execute {
    use super::*;
    use cosmwasm_std::Uint128;

    pub fn increment(deps: DepsMut) -> Result<Response, ContractError> {
        STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
            state.count += 1;
            Ok(state)
        })?;

        Ok(Response::new().add_attribute("action", "increment"))
    }

    pub fn reset(deps: DepsMut, info: MessageInfo, count: i32) -> Result<Response, ContractError> {
        STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
            if info.sender != state.owner {
                return Err(ContractError::Unauthorized {});
            }
            state.count = count;
            Ok(state)
        })?;
        Ok(Response::new().add_attribute("action", "reset"))
    }

    pub fn create_gaa(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        year: u32,
        total_amount: Uint128,
        status: String,
        token_name: String,
        token_symbol: String,
        token_decimals: u8,
        cw20_code_id: u64,
    ) -> Result<Response, ContractError> {
        // Check if GAA already exists
        if GAAS.has(deps.storage, id.clone()) {
            return Err(ContractError::AlreadyExists { entity: "GAA".to_string() });
        }

        // Create CW20 token instantiate message manually
        let token_instantiate_msg = json!({
            "name": token_name.clone(),
            "symbol": token_symbol.clone(),
            "decimals": token_decimals,
            "initial_balances": [],
            "mint": {
                "minter": env.contract.address.to_string(), // Set contract as minter
                "cap": null
            },
            "marketing": null
        });

        // Create submessage to instantiate CW20 token
        let token_instantiate_submsg = SubMsg::reply_on_success(
            CosmosMsg::Wasm(WasmMsg::Instantiate {
                admin: Some(info.sender.to_string()),
                code_id: cw20_code_id, // CW20 code ID passed as parameter
                msg: to_json_binary(&token_instantiate_msg)?,
                funds: vec![],
                label: format!("GAA {} Token", id),
            }),
            1, // reply ID
        );

        let gaa = GAA {
            id: id.clone(),
            year,
            total_amount,
            description: None,
            available_amount_for_paps: total_amount,
            token_address: None, // Will be set after token creation
            status: status.clone(),
            pap_count: 0, // Initialize PAP count to 0
            created_by: info.sender.clone(),
            created_at: env.block.time.seconds(),
        };

        GAAS.save(deps.storage, id.clone(), &gaa)?;
        
        // Save to year index for efficient year-based queries
        GAAS_BY_YEAR.save(deps.storage, (year, id.clone()), &())?;
        
        // Store the GAA ID temporarily to track which GAA the token belongs to
        PENDING_GAA.save(deps.storage, &id)?;

        Ok(Response::new()
            .add_submessage(token_instantiate_submsg)
            .add_attribute("action", "create_gaa")
            .add_attribute("gaa_id", id)
            .add_attribute("year", year.to_string())
            .add_attribute("token_name", token_name)
            .add_attribute("token_symbol", token_symbol)
            .add_attribute("total_amount", total_amount.to_string()))
    }

    pub fn create_pap(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        gaa_id: String,
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
    ) -> Result<Response, ContractError> {
        // Check if GAA exists and has sufficient available amount
        let mut gaa = GAAS.load(deps.storage, gaa_id.clone())
            .map_err(|_| ContractError::NotFound { entity: "GAA".to_string() })?;

        // DEBUG: Log GAA state during PAP creation
        let debug_msg = format!("DEBUG PAP Creation - GAA ID: {}, Available: {}, Requested: {}, Total: {}", 
            gaa_id, gaa.available_amount_for_paps, amount, gaa.total_amount);
        
        if gaa.available_amount_for_paps < amount {
            let error_msg = format!("Insufficient GAA balance. Available: {}, Requested: {}", gaa.available_amount_for_paps, amount);
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err(error_msg)));
        }

        // Check if PAP already exists
        if PAPS.has(deps.storage, (gaa_id.clone(), id.clone())) {
            return Err(ContractError::AlreadyExists { entity: "PAP".to_string() });
        }

        // Deduct amount from GAA available balance and increment PAP count
        gaa.available_amount_for_paps = gaa.available_amount_for_paps.checked_sub(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        
        // Assign idx from current pap_count (before incrementing)
        let pap_idx = gaa.pap_count;
        gaa.pap_count += 1;
        GAAS.save(deps.storage, gaa_id.clone(), &gaa)?;

        let pap = PAP {
            id: id.clone(),
            gaa_id: gaa_id.clone(),
            idx: pap_idx, // Auto-assigned index within GAA
            
            // UACS and Budget Classification Fields (from backend)
            sorder: sorder,
            department: department,
            uacs_dpt_dsc: uacs_dpt_dsc,
            agency: agency,
            uacs_agy_dsc: uacs_agy_dsc,
            prexc_fpap_id: prexc_fpap_id,
            prexc_level: prexc_level,
            dsc: dsc,
            oper_unit: oper_unit,
            uacs_oper_dsc: uacs_oper_dsc,
            uacs_reg_id: uacs_reg_id,
            uacs_operdiv_id: uacs_operdiv_id,
            uacs_div_dsc: uacs_div_dsc,
            fund_cd: fund_cd,
            uacs_fundsubcat_dsc: uacs_fundsubcat_dsc,
            uacs_exp_cd: uacs_exp_cd,
            uacs_exp_dsc: uacs_exp_dsc,
            uacs_sobj_cd: uacs_sobj_cd,
            uacs_sobj_dsc: uacs_sobj_dsc,
            amt: amount,
            available_amount_for_saros: amount, // Initially all PAP amount is available for SAROs
            created_by: info.sender.clone(),
            created_at: env.block.time.seconds(),
        };

        // Save with composite key (gaa_id, pap_id)
        PAPS.save(deps.storage, (gaa_id.clone(), id.clone()), &pap)?;
        
        // Save to idx index map for numeric index lookups
        PAPS_BY_IDX.save(deps.storage, (gaa_id.clone(), pap_idx), &id)?;
        
        // Save composite key hash index for lookups by business key
        let composite_key_hash = compute_pap_composite_key_hash(
            gaa.year,
            &pap.department,
            &pap.agency,
            &pap.prexc_fpap_id,
            &pap.oper_unit,
            &pap.fund_cd,
            &pap.uacs_sobj_cd,
            &pap.uacs_reg_id,
        );
        PAPS_BY_COMPOSITE_KEY.save(deps.storage, composite_key_hash.clone(), &id)?;

        Ok(Response::new()
            .add_attribute("action", "create_pap")
            .add_attribute("pap_id", id)
            .add_attribute("gaa_id", gaa_id.clone())
            .add_attribute("amount_allocated", amount.to_string())
            .add_attribute("gaa_remaining", gaa.available_amount_for_paps.to_string())
            .add_attribute("composite_key_hash", composite_key_hash))
    }

    pub fn create_saro(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        pap_id: String,
        saro_number: String,
        amount: Uint128,
        release_date: Option<String>,
        department: Option<String>,
        agency: Option<String>,
        operating_unit: Option<String>,
        purpose: Option<String>,
    ) -> Result<Response, ContractError> {
        // Need gaa_id to load PAP with composite key
        // First, we need to find the gaa_id from the pap_id
        // For now, we'll iterate to find it (can be optimized with a reverse index if needed)
        let pap_result: Result<PAP, _> = PAPS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == pap_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "PAP".to_string() })?
            .map(|(_, pap)| pap);
        
        let mut pap = pap_result?;
        let gaa_id = pap.gaa_id.clone();

        if pap.available_amount_for_saros < amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err("Insufficient PAP balance")));
        }

        // Check if SARO already exists
        if SAROS.has(deps.storage, (pap_id.clone(), id.clone())) {
            return Err(ContractError::AlreadyExists { entity: "SARO".to_string() });
        }

        // Deduct amount from PAP available balance
        pap.available_amount_for_saros = pap.available_amount_for_saros.checked_sub(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        // Save PAP with composite key
        PAPS.save(deps.storage, (gaa_id, pap_id.clone()), &pap)?;

        let saro = SARO {
            id: id.clone(),
            pap_id: pap_id.clone(),
            saro_number,
            amount,
            release_date: None, // From backend (timestamp)
            department, // From backend
            agency, // From backend
            operating_unit, // From backend
            purpose, // From backend
            
            // Blockchain-specific fields
            available_amount_for_obligations: amount, // Initially all amount available for obligations
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save with composite key (pap_id, saro_id)
        SAROS.save(deps.storage, (pap_id.clone(), id.clone()), &saro)?;

        // No index update needed with composite keys!

        Ok(Response::new()
            .add_attribute("action", "create_saro")
            .add_attribute("saro_id", id)
            .add_attribute("pap_id", pap_id))
    }

    pub fn create_obligation(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        saro_id: String,  // Changed from nca_id to saro_id
        obligation_number: String,
        amount: Uint128,
        description: Option<String>,
        payee: Option<String>,
        obligation_date: Option<u64>,  // Unix timestamp
    ) -> Result<Response, ContractError> {
        // Need pap_id to load SARO with composite key
        // Find the SARO by iterating (can be optimized with reverse index if needed)
        let saro_result: Result<SARO, _> = SAROS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == saro_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "SARO".to_string() })?
            .map(|(_, saro)| saro);
        
        let mut saro = saro_result?;
        let pap_id = saro.pap_id.clone();

        if saro.available_amount_for_obligations < amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err("Insufficient SARO balance for obligations")));
        }

        // Check if Obligation already exists
        if OBLIGATIONS.has(deps.storage, (saro_id.clone(), id.clone())) {
            return Err(ContractError::AlreadyExists { entity: "Obligation".to_string() });
        }

        // Deduct amount from SARO available balance for obligations
        saro.available_amount_for_obligations = saro.available_amount_for_obligations.checked_sub(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        // Save SARO with composite key
        SAROS.save(deps.storage, (pap_id, saro_id.clone()), &saro)?;

        let obligation = Obligation {
            id: id.clone(),
            saro_id: saro_id.clone(),  // Obligation is a child of SARO
            obligation_number,
            amount,
            liquidated_amount_from_disbursements: Uint128::zero(), // liquidated amount from DisbursementVouchers (blockchain-specific)
            available_amount_for_disbursement_vouchers: amount, // Available amount for Disbursements (blockchain-specific)
            department: Some("Unknown".to_string()), // New field from backend - default value
            purpose: None, // New field from backend
            obligation_date: obligation_date, // New field from backend
            status: Some("pending".to_string()), // New field from backend
            
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save with composite key (saro_id, obligation_id)
        OBLIGATIONS.save(deps.storage, (saro_id.clone(), id.clone()), &obligation)?;

        // No index update needed with composite keys!

        Ok(Response::new()
            .add_attribute("action", "create_obligation")
            .add_attribute("obligation_id", id)
            .add_attribute("saro_id", saro_id))
    }

    pub fn create_nca(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
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
    ) -> Result<Response, ContractError> {
        // Basic validation: require at least one SARO ID
        if saro_ids.is_empty() {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err("At least one SARO ID is required for NCA")));
        }

        // Ensure all referenced SAROs exist (but do not modify their balances)
        for saro_id in &saro_ids {
            let _saro: SARO = SAROS
                .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
                .find(|item| {
                    if let Ok((key, _)) = item {
                        key.1 == *saro_id
                    } else {
                        false
                    }
                })
                .ok_or_else(|| ContractError::NotFound { entity: "SARO".to_string() })?
                .map(|(_, saro)| saro)?;
        }

        // Check if NCA already exists by ID
        if NCAS_BY_ID.has(deps.storage, id.clone()) {
            return Err(ContractError::AlreadyExists { entity: "NCA".to_string() });
        }

        // Timestamps are already in Unix format from the API, no parsing needed
        let nca = NCA {
            id: id.clone(),
            saro_ids: saro_ids.clone(),
            nca_number,
            amount,
            approved_date,  // Direct assignment - already Unix timestamp
            issue_date,     // Direct assignment - already Unix timestamp
            release_date,   // Direct assignment - already Unix timestamp
            department,
            agency,
            operating_unit,
            purpose,
            cancel_remarks,
            release_type_cd,
            // Initially nothing has been liquidated from this NCA
            liquidated_amount_from_disbursements: Uint128::zero(),
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save canonically by ID
        NCAS_BY_ID.save(deps.storage, id.clone(), &nca)?;

        // Create index entries for each SARO parent
        for saro_id in &saro_ids {
            NCAS_BY_SARO.save(deps.storage, (saro_id.clone(), id.clone()), &())?;
        }

        Ok(Response::new()
            .add_attribute("action", "create_nca")
            .add_attribute("nca_id", id)
            .add_attribute("saro_ids", saro_ids.join(",")))
    }

    pub fn create_disbursement_voucher(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        obligation_id: String,
        nca_id: String,
        dv_number: String,
        amount: Uint128,
        description: Option<String>,
        payee: Option<String>,
        disbursement_voucher_date: Option<u64>,  // Unix timestamp
    ) -> Result<Response, ContractError> {
        // Find Obligation by iterating (need saro_id for composite key)
        let obligation_result: Result<Obligation, _> = OBLIGATIONS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == obligation_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "Obligation".to_string() })?
            .map(|(_, obligation)| obligation);
        
        let mut obligation = obligation_result?;
        let saro_id = obligation.saro_id.clone();

        // Find NCA canonically by ID (multi-SARO NCAs stored in NCAS_BY_ID)
        let mut nca = NCAS_BY_ID
            .load(deps.storage, nca_id.clone())
            .map_err(|_| ContractError::NotFound { entity: "NCA".to_string() })?;

        // Validate that both have sufficient available amounts
        if obligation.available_amount_for_disbursement_vouchers < amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err("Insufficient Obligation balance for DV")));
        }

        // Check if DisbursementVoucher already exists
        if DISBURSEMENT_VOUCHERS.has(deps.storage, (obligation_id.clone(), nca_id.clone(), id.clone())) {
            return Err(ContractError::AlreadyExists { entity: "DisbursementVoucher".to_string() });
        }

        // Deduct amount from Obligation
        obligation.available_amount_for_disbursement_vouchers = obligation.available_amount_for_disbursement_vouchers.checked_sub(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        // Save Obligation with composite key
        OBLIGATIONS.save(deps.storage, (saro_id.clone(), obligation_id.clone()), &obligation)?;

        let dv = DisbursementVoucher {
            id: id.clone(),
            nca_id: nca_id.clone(), // From backend (order matches backend)
            obligation_id: obligation_id.clone(),
            dv_number,
            amount,
            liquidated_amount_from_disbursements: Uint128::zero(), // Initially no amount has been liquidated by Disbursements
            description,
            payee,
            voucher_date: disbursement_voucher_date, // New field from backend
            status: Some("pending".to_string()), // New field from backend
            
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save with composite key (obligation_id, nca_id, dv_id)
        DISBURSEMENT_VOUCHERS.save(deps.storage, (obligation_id.clone(), nca_id.clone(), id.clone()), &dv)?;

        // No index updates needed with composite keys!

        Ok(Response::new()
            .add_attribute("action", "create_disbursement_voucher")
            .add_attribute("dv_id", id)
            .add_attribute("obligation_id", obligation_id)
            .add_attribute("nca_id", nca_id))
    }

    pub fn create_disbursement(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        disbursement_voucher_id: String,
        disbursement_number: String,
        amount: Uint128,
        recipient_qadena_address: String,
        disbursement_date: u64,
        description: Option<String>,
        payee: Option<String>,
        payment_method: Option<String>,
        reference_number: Option<String>,
        status: Option<String>,
    ) -> Result<Response, ContractError> {
        // Validate and convert recipient to address
        let recipient_addr = deps.api.addr_validate(&recipient_qadena_address)?;

        // Find DisbursementVoucher by iterating (need obligation_id and nca_id for composite key)
        let dv_result: Result<DisbursementVoucher, _> = DISBURSEMENT_VOUCHERS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.2 == disbursement_voucher_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "DisbursementVoucher".to_string() })?
            .map(|(_, dv)| dv);
        
        let mut dv = dv_result?;
        let obligation_id = dv.obligation_id.clone();
        let nca_id = dv.nca_id.clone();

        // Load NCA to check available balance for disbursements
        let mut nca = NCAS_BY_ID
            .load(deps.storage, nca_id.clone())
            .map_err(|_| ContractError::NotFound { entity: "NCA".to_string() })?;

        // Load Obligation to update liquidated amount
        let obligation_result: Result<Obligation, _> = OBLIGATIONS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == obligation_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "Obligation".to_string() })?
            .map(|(_, obl)| obl);
        let mut obligation = obligation_result?;

        // Validate NCA has enough remaining (amount - liquidated) before making changes
        let nca_remaining = nca
            .amount
            .checked_sub(nca.liquidated_amount_from_disbursements)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;

        if nca_remaining < amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err(
                format!("Insufficient NCA balance for disbursement. Available: {}, Requested: {}", 
                       nca_remaining, amount))));
        }

        // Check that DV won't exceed its total amount when liquidated
        let new_dv_liquidated = dv.liquidated_amount_from_disbursements.checked_add(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        if new_dv_liquidated > dv.amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err(
                format!("DV liquidation would exceed total amount. Current: {}, Adding: {}, Total: {}", 
                       dv.liquidated_amount_from_disbursements, amount, dv.amount))));
        }

        // Check that Obligation won't exceed its total amount when liquidated
        let new_obligation_liquidated = obligation.liquidated_amount_from_disbursements.checked_add(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        if new_obligation_liquidated > obligation.amount {
            return Err(ContractError::Std(cosmwasm_std::StdError::generic_err(
                format!("Obligation liquidation would exceed total amount. Current: {}, Adding: {}, Total: {}", 
                       obligation.liquidated_amount_from_disbursements, amount, obligation.amount))));
        }

        // Check if Disbursement already exists
        if DISBURSEMENTS.has(deps.storage, (disbursement_voucher_id.clone(), id.clone())) {
            return Err(ContractError::AlreadyExists { entity: "Disbursement".to_string() });
        }

        // Trace back to GAA to get token address
        // DV -> Obligation -> SARO -> PAP -> GAA
        
        // Get SARO ID from the already loaded obligation
        let saro_id = obligation.saro_id.clone();

        // Get SARO to find PAP
        let saro_result: Result<SARO, _> = SAROS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == saro_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "SARO".to_string() })?
            .map(|(_, saro)| saro);
        let saro = saro_result?;
        let pap_id = saro.pap_id.clone();

        // Get PAP to find GAA
        let pap_result: Result<PAP, _> = PAPS
            .range(deps.storage, None, None, cosmwasm_std::Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == pap_id
                } else {
                    false
                }
            })
            .ok_or_else(|| ContractError::NotFound { entity: "PAP".to_string() })?
            .map(|(_, pap)| pap);
        let pap = pap_result?;
        let gaa_id = pap.gaa_id.clone();

        // Get token address for this GAA
        let token_info = TOKEN_INFO.load(deps.storage, gaa_id.clone())?;
        let token_addr = token_info.token_address;

        // Update balances: increase NCA liquidated amount, and DV/Obligation liquidated amounts
        nca.liquidated_amount_from_disbursements = nca
            .liquidated_amount_from_disbursements
            .checked_add(amount)
            .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("Arithmetic overflow")))?;
        
        dv.liquidated_amount_from_disbursements = new_dv_liquidated;
        
        obligation.liquidated_amount_from_disbursements = new_obligation_liquidated;

        // Save updated entities
        NCAS_BY_ID.save(deps.storage, nca_id.clone(), &nca)?;
        DISBURSEMENT_VOUCHERS.save(deps.storage, (obligation_id.clone(), nca_id.clone(), disbursement_voucher_id.clone()), &dv)?;
        OBLIGATIONS.save(deps.storage, (saro_id.clone(), obligation_id.clone()), &obligation)?;

        let disbursement = Disbursement {
            id: id.clone(),
            dv_id: disbursement_voucher_id.clone(),
            recipient: recipient_addr.clone(),
            amount,
            transaction_hash: None,
            disbursement_date: disbursement_date,
            created_by: info.sender.clone(),
            created_at: env.block.time.seconds(),
        };

        // Save with composite key (dv_id, disbursement_id)
        DISBURSEMENTS.save(deps.storage, (disbursement_voucher_id.clone(), id.clone()), &disbursement)?;

        // Create CW20 token transfer message
        let transfer_msg = Cw20ExecuteMsg::Transfer {
            recipient: recipient_addr.to_string(),
            amount,
        };

        let transfer_cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token_addr.to_string(),
            msg: to_json_binary(&transfer_msg)?,
            funds: vec![],
        });

        Ok(Response::new()
            .add_message(transfer_cosmos_msg)
            .add_attribute("action", "create_disbursement")
            .add_attribute("disbursement_id", id)
            .add_attribute("dv_id", disbursement_voucher_id)
            .add_attribute("recipient", recipient_addr.to_string())
            .add_attribute("amount", amount.to_string())
            .add_attribute("token_address", token_addr.to_string()))
    }

    // PhilGEPS Procurement Contract functions
    pub fn create_procurement_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
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
    ) -> Result<Response, ContractError> {
        // Check if contract already exists
        if PHILGEPS_CONTRACTS.has(deps.storage, id.clone()) {
            return Err(ContractError::AlreadyExists { entity: "ProcurementContract".to_string() });
        }

        // Load or initialize PhilGEPS state
        let mut philgeps_state = PHILGEPS_STATE
            .may_load(deps.storage)?
            .unwrap_or(PhilGEPSState { contract_count: 0 });
        
        // Assign next index
        let idx = philgeps_state.contract_count;
        philgeps_state.contract_count += 1;

        let contract = ProcurementContract {
            id: id.clone(),
            idx,
            reference_id: reference_id.clone(),
            contract_no: contract_no.clone(),
            award_title,
            notice_title,
            awardee_name,
            organization_name,
            area_of_delivery,
            business_category,
            contract_amount,
            award_date,
            award_status,
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save contract and update indices
        PHILGEPS_CONTRACTS.save(deps.storage, id.clone(), &contract)?;
        PHILGEPS_CONTRACTS_BY_IDX.save(deps.storage, idx, &id)?;
        
        // Save reference_id index if provided
        if let Some(ref ref_id) = reference_id {
            if !ref_id.is_empty() {
                PHILGEPS_CONTRACTS_BY_REF_ID.save(deps.storage, ref_id.clone(), &id)?;
            }
        }
        
        // Save contract_no index if provided
        if let Some(ref cn) = contract_no {
            if !cn.is_empty() {
                PHILGEPS_CONTRACTS_BY_CONTRACT_NO.save(deps.storage, cn.clone(), &id)?;
            }
        }
        
        PHILGEPS_STATE.save(deps.storage, &philgeps_state)?;

        Ok(Response::new()
            .add_attribute("action", "create_procurement_contract")
            .add_attribute("id", id)
            .add_attribute("idx", idx.to_string())
            .add_attribute("contract_amount", contract_amount.to_string()))
    }

    pub fn delete_procurement_contract(
        deps: DepsMut,
        info: MessageInfo,
        id: String,
    ) -> Result<Response, ContractError> {
        // Check if contract exists
        if !PHILGEPS_CONTRACTS.has(deps.storage, id.clone()) {
            return Err(ContractError::NotFound { entity: "ProcurementContract".to_string() });
        }

        // Only owner can delete (optional - you may want different authorization)
        let state = STATE.load(deps.storage)?;
        if info.sender != state.owner {
            return Err(ContractError::Unauthorized {});
        }

        PHILGEPS_CONTRACTS.remove(deps.storage, id.clone());

        Ok(Response::new()
            .add_attribute("action", "delete_procurement_contract")
            .add_attribute("id", id))
    }

    // DPWH Contract functions
    #[allow(clippy::too_many_arguments)]
    pub fn create_dpwh_contract(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
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
        components: Option<Vec<DPWHComponentMsg>>,
        bidders: Option<Vec<DPWHBidderMsg>>,
        coordinates: Option<Vec<DPWHCoordinateMsg>>,
    ) -> Result<Response, ContractError> {
        // Check if contract already exists
        if DPWH_CONTRACTS.has(deps.storage, contract_id.clone()) {
            return Err(ContractError::AlreadyExists { entity: "DPWHContract".to_string() });
        }

        // Get or initialize DPWH state
        let mut dpwh_state = DPWH_STATE.may_load(deps.storage)?.unwrap_or(DPWHState {
            contract_count: 0,
        });

        let idx = dpwh_state.contract_count;
        dpwh_state.contract_count += 1;

        let contract = DPWHContract {
            contract_id: contract_id.clone(),
            idx,
            description,
            category,
            status: status.clone(),
            budget,
            amount_paid,
            progress,
            region: region.clone(),
            province,
            infra_type,
            latitude,
            longitude,
            verified,
            infra_type_1,
            contractor,
            start_date,
            completion_date,
            infra_year: infra_year.clone(),
            contract_effectivity_date,
            expiry_date,
            program_name,
            source_of_funds,
            contract_name,
            award_amount,
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        // Save contract
        DPWH_CONTRACTS.save(deps.storage, contract_id.clone(), &contract)?;
        DPWH_CONTRACTS_BY_IDX.save(deps.storage, idx, &contract_id)?;

        // Save indexes for filtering
        if let Some(ref r) = region {
            DPWH_CONTRACTS_BY_REGION.save(deps.storage, (r.clone(), contract_id.clone()), &())?;
        }
        if let Some(ref s) = status {
            DPWH_CONTRACTS_BY_STATUS.save(deps.storage, (s.clone(), contract_id.clone()), &())?;
        }
        if let Some(ref y) = infra_year {
            DPWH_CONTRACTS_BY_YEAR.save(deps.storage, (y.clone(), contract_id.clone()), &())?;
        }

        // Save nested components
        if let Some(comps) = components {
            for (i, comp) in comps.into_iter().enumerate() {
                let component = DPWHComponent {
                    contract_id: contract_id.clone(),
                    idx: i as u32,
                    component_id: comp.component_id,
                    description: comp.description,
                    infra_type: comp.infra_type,
                    type_of_work: comp.type_of_work,
                    region: comp.region,
                    province: comp.province,
                    latitude: comp.latitude,
                    longitude: comp.longitude,
                    coordinate_source: comp.coordinate_source,
                    location_verified: comp.location_verified,
                };
                DPWH_COMPONENTS.save(deps.storage, (contract_id.clone(), i as u32), &component)?;
            }
        }

        // Save nested bidders
        if let Some(bids) = bidders {
            for (i, bid) in bids.into_iter().enumerate() {
                let bidder = DPWHBidder {
                    contract_id: contract_id.clone(),
                    idx: i as u32,
                    name: bid.name,
                    pcab_id: bid.pcab_id,
                    participation: bid.participation,
                    is_winner: bid.is_winner,
                };
                DPWH_BIDDERS.save(deps.storage, (contract_id.clone(), i as u32), &bidder)?;
            }
        }

        // Save nested coordinates
        if let Some(coords) = coordinates {
            for (i, coord) in coords.into_iter().enumerate() {
                let coordinate = DPWHCoordinate {
                    contract_id: contract_id.clone(),
                    idx: i as u32,
                    component_id: coord.component_id,
                    description: coord.description,
                    latitude: coord.latitude,
                    longitude: coord.longitude,
                    source: coord.source,
                    location_verified: coord.location_verified,
                };
                DPWH_COORDINATES.save(deps.storage, (contract_id.clone(), i as u32), &coordinate)?;
            }
        }

        // Save updated state
        DPWH_STATE.save(deps.storage, &dpwh_state)?;

        Ok(Response::new()
            .add_attribute("action", "create_dpwh_contract")
            .add_attribute("contract_id", contract_id)
            .add_attribute("idx", idx.to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_dpwh_contract(
        deps: DepsMut,
        info: MessageInfo,
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
    ) -> Result<Response, ContractError> {
        let mut contract = DPWH_CONTRACTS.load(deps.storage, contract_id.clone())
            .map_err(|_| ContractError::NotFound { entity: "DPWHContract".to_string() })?;

        // Update fields if provided
        if description.is_some() { contract.description = description; }
        if category.is_some() { contract.category = category; }
        if status.is_some() { contract.status = status; }
        if budget.is_some() { contract.budget = budget; }
        if amount_paid.is_some() { contract.amount_paid = amount_paid; }
        if progress.is_some() { contract.progress = progress; }
        if region.is_some() { contract.region = region; }
        if province.is_some() { contract.province = province; }
        if infra_type.is_some() { contract.infra_type = infra_type; }
        if latitude.is_some() { contract.latitude = latitude; }
        if longitude.is_some() { contract.longitude = longitude; }
        if verified.is_some() { contract.verified = verified; }
        if contractor.is_some() { contract.contractor = contractor; }
        if infra_year.is_some() { contract.infra_year = infra_year; }
        if program_name.is_some() { contract.program_name = program_name; }
        if source_of_funds.is_some() { contract.source_of_funds = source_of_funds; }

        DPWH_CONTRACTS.save(deps.storage, contract_id.clone(), &contract)?;

        Ok(Response::new()
            .add_attribute("action", "update_dpwh_contract")
            .add_attribute("contract_id", contract_id))
    }

    pub fn delete_dpwh_contract(
        deps: DepsMut,
        info: MessageInfo,
        contract_id: String,
    ) -> Result<Response, ContractError> {
        let contract = DPWH_CONTRACTS.load(deps.storage, contract_id.clone())
            .map_err(|_| ContractError::NotFound { entity: "DPWHContract".to_string() })?;

        // Only owner can delete
        let state = STATE.load(deps.storage)?;
        if info.sender != state.owner {
            return Err(ContractError::Unauthorized {});
        }

        // Remove indexes
        if let Some(ref r) = contract.region {
            DPWH_CONTRACTS_BY_REGION.remove(deps.storage, (r.clone(), contract_id.clone()));
        }
        if let Some(ref s) = contract.status {
            DPWH_CONTRACTS_BY_STATUS.remove(deps.storage, (s.clone(), contract_id.clone()));
        }
        if let Some(ref y) = contract.infra_year {
            DPWH_CONTRACTS_BY_YEAR.remove(deps.storage, (y.clone(), contract_id.clone()));
        }

        // Remove nested data (iterate and remove)
        let components: Vec<_> = DPWH_COMPONENTS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<StdResult<Vec<_>>>()?;
        for (idx, _) in components {
            DPWH_COMPONENTS.remove(deps.storage, (contract_id.clone(), idx));
        }

        let bidders: Vec<_> = DPWH_BIDDERS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<StdResult<Vec<_>>>()?;
        for (idx, _) in bidders {
            DPWH_BIDDERS.remove(deps.storage, (contract_id.clone(), idx));
        }

        let coordinates: Vec<_> = DPWH_COORDINATES
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .collect::<StdResult<Vec<_>>>()?;
        for (idx, _) in coordinates {
            DPWH_COORDINATES.remove(deps.storage, (contract_id.clone(), idx));
        }

        // Remove main contract
        DPWH_CONTRACTS.remove(deps.storage, contract_id.clone());

        Ok(Response::new()
            .add_attribute("action", "delete_dpwh_contract")
            .add_attribute("contract_id", contract_id))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_dpwh_component(
        deps: DepsMut,
        info: MessageInfo,
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
    ) -> Result<Response, ContractError> {
        // Verify contract exists
        if !DPWH_CONTRACTS.has(deps.storage, contract_id.clone()) {
            return Err(ContractError::NotFound { entity: "DPWHContract".to_string() });
        }

        // Find next index
        let existing: Vec<_> = DPWH_COMPONENTS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Descending)
            .take(1)
            .collect::<StdResult<Vec<_>>>()?;
        
        let next_idx = existing.first().map(|(idx, _)| idx + 1).unwrap_or(0);

        let component = DPWHComponent {
            contract_id: contract_id.clone(),
            idx: next_idx,
            component_id,
            description,
            infra_type,
            type_of_work,
            region,
            province,
            latitude,
            longitude,
            coordinate_source,
            location_verified,
        };

        DPWH_COMPONENTS.save(deps.storage, (contract_id.clone(), next_idx), &component)?;

        Ok(Response::new()
            .add_attribute("action", "add_dpwh_component")
            .add_attribute("contract_id", contract_id)
            .add_attribute("idx", next_idx.to_string()))
    }

    pub fn add_dpwh_bidder(
        deps: DepsMut,
        info: MessageInfo,
        contract_id: String,
        name: Option<String>,
        pcab_id: Option<String>,
        participation: Option<u32>,
        is_winner: Option<bool>,
    ) -> Result<Response, ContractError> {
        // Verify contract exists
        if !DPWH_CONTRACTS.has(deps.storage, contract_id.clone()) {
            return Err(ContractError::NotFound { entity: "DPWHContract".to_string() });
        }

        // Find next index
        let existing: Vec<_> = DPWH_BIDDERS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Descending)
            .take(1)
            .collect::<StdResult<Vec<_>>>()?;
        
        let next_idx = existing.first().map(|(idx, _)| idx + 1).unwrap_or(0);

        let bidder = DPWHBidder {
            contract_id: contract_id.clone(),
            idx: next_idx,
            name,
            pcab_id,
            participation,
            is_winner,
        };

        DPWH_BIDDERS.save(deps.storage, (contract_id.clone(), next_idx), &bidder)?;

        Ok(Response::new()
            .add_attribute("action", "add_dpwh_bidder")
            .add_attribute("contract_id", contract_id)
            .add_attribute("idx", next_idx.to_string()))
    }

    pub fn add_dpwh_coordinate(
        deps: DepsMut,
        info: MessageInfo,
        contract_id: String,
        component_id: Option<String>,
        description: Option<String>,
        latitude: Option<String>,
        longitude: Option<String>,
        source: Option<String>,
        location_verified: Option<bool>,
    ) -> Result<Response, ContractError> {
        // Verify contract exists
        if !DPWH_CONTRACTS.has(deps.storage, contract_id.clone()) {
            return Err(ContractError::NotFound { entity: "DPWHContract".to_string() });
        }

        // Find next index
        let existing: Vec<_> = DPWH_COORDINATES
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Descending)
            .take(1)
            .collect::<StdResult<Vec<_>>>()?;
        
        let next_idx = existing.first().map(|(idx, _)| idx + 1).unwrap_or(0);

        let coordinate = DPWHCoordinate {
            contract_id: contract_id.clone(),
            idx: next_idx,
            component_id,
            description,
            latitude,
            longitude,
            source,
            location_verified,
        };

        DPWH_COORDINATES.save(deps.storage, (contract_id.clone(), next_idx), &coordinate)?;

        Ok(Response::new()
            .add_attribute("action", "add_dpwh_coordinate")
            .add_attribute("contract_id", contract_id)
            .add_attribute("idx", next_idx.to_string()))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_json_binary(&query::count(deps)?),
        QueryMsg::GetGAA { id } => to_json_binary(&query::get_gaa(deps, id)?),
        QueryMsg::GetGAAs { start_after, limit } => to_json_binary(&query::get_gaas(deps, start_after, limit)?),
        QueryMsg::GetGAAByYear { year, start_after, limit } => to_json_binary(&query::get_gaa_by_year(deps, year, start_after, limit)?),
        QueryMsg::GetPAP { gaa_id, pap_id } => to_json_binary(&query::get_pap(deps, gaa_id, pap_id)?),
        QueryMsg::GetPAPsByGAA { gaa_id, start_after, limit } => to_json_binary(&query::get_paps_by_gaa(deps, gaa_id, start_after, limit)?),
        QueryMsg::GetPAPsByGAANumIdx { gaa_id, start_idx, limit } => to_json_binary(&query::get_paps_by_gaa_num_idx(deps, gaa_id, start_idx, limit)?),
        QueryMsg::GetPAPByCompositeKey { composite_key_hash } => to_json_binary(&query::get_pap_by_composite_key(deps, composite_key_hash)?),
        QueryMsg::GetSARO { pap_id, saro_id } => to_json_binary(&query::get_saro(deps, pap_id, saro_id)?),
        QueryMsg::GetSAROsByPAP { pap_id, start_after, limit } => to_json_binary(&query::get_saros_by_pap(deps, pap_id, start_after, limit)?),
        QueryMsg::GetObligation { saro_id, obligation_id } => to_json_binary(&query::get_obligation(deps, saro_id, obligation_id)?),
        QueryMsg::GetObligationsBySARO { saro_id, start_after, limit } => to_json_binary(&query::get_obligations_by_saro(deps, saro_id, start_after, limit)?),
        QueryMsg::GetNCA { nca_id } => to_json_binary(&query::get_nca(deps, nca_id)?),
        QueryMsg::GetNCAsBySARO { saro_id, start_after, limit } => to_json_binary(&query::get_ncas_by_saro(deps, saro_id, start_after, limit)?),
        QueryMsg::GetDisbursementVoucher { obligation_id, nca_id, dv_id } => to_json_binary(&query::get_disbursement_voucher(deps, obligation_id, nca_id, dv_id)?),
        QueryMsg::GetDisbursementVouchersByObligation { obligation_id, start_after, limit } => to_json_binary(&query::get_disbursement_vouchers_by_obligation(deps, obligation_id, start_after, limit)?),
        QueryMsg::GetDisbursementVouchersByNCA { nca_id, start_after, limit } => to_json_binary(&query::get_disbursement_vouchers_by_nca(deps, nca_id, start_after, limit)?),
        QueryMsg::GetDisbursement { dv_id, disbursement_id } => to_json_binary(&query::get_disbursement(deps, dv_id, disbursement_id)?),
        QueryMsg::GetDisbursementsByDV { dv_id, start_after, limit } => to_json_binary(&query::get_disbursements_by_dv(deps, dv_id, start_after, limit)?),
        QueryMsg::GetBudgetHierarchy { 
            gaa_id, 
            pap_start_after,
            paps_per_page, 
            saros_per_pap, 
            ncas_per_saro, 
            obligations_per_saro, 
            dvs_per_parent, 
            disbursements_per_dv 
        } => to_json_binary(&query::get_budget_hierarchy(
            deps, 
            gaa_id, 
            pap_start_after,
            paps_per_page, 
            saros_per_pap, 
            ncas_per_saro, 
            obligations_per_saro, 
            dvs_per_parent, 
            disbursements_per_dv
        )?),
        QueryMsg::GetTokenInfo { gaa_id } => to_json_binary(&query::get_token_info(deps, gaa_id)?),
        QueryMsg::GetTokenBalance { gaa_id, address } => to_json_binary(&query::get_token_balance(deps, gaa_id, address)?),
        QueryMsg::GetProcurementContract { id } => to_json_binary(&query::get_procurement_contract(deps, id)?),
        QueryMsg::GetProcurementContracts { start_after, limit, organization_name, awardee_name, business_category } => {
            to_json_binary(&query::get_procurement_contracts(deps, start_after, limit, organization_name, awardee_name, business_category)?)
        },
        QueryMsg::GetProcurementContractsByNumIdx { start_idx, limit } => {
            to_json_binary(&query::get_procurement_contracts_by_num_idx(deps, start_idx, limit)?)
        },
        QueryMsg::GetPhilGEPSState {} => to_json_binary(&query::get_philgeps_state(deps)?),
        QueryMsg::GetProcurementContractByReferenceId { reference_id } => {
            to_json_binary(&query::get_procurement_contract_by_reference_id(deps, reference_id)?)
        },
        QueryMsg::GetProcurementContractByContractNo { contract_no } => {
            to_json_binary(&query::get_procurement_contract_by_contract_no(deps, contract_no)?)
        },
        // DPWH queries
        QueryMsg::GetDPWHContract { contract_id } => {
            to_json_binary(&query::get_dpwh_contract(deps, contract_id)?)
        },
        QueryMsg::GetDPWHContracts { start_after, limit, region, status, infra_year } => {
            to_json_binary(&query::get_dpwh_contracts(deps, start_after, limit, region, status, infra_year)?)
        },
        QueryMsg::GetDPWHContractsByNumIdx { start_idx, limit } => {
            to_json_binary(&query::get_dpwh_contracts_by_num_idx(deps, start_idx, limit)?)
        },
        QueryMsg::GetDPWHContractsByRegion { region, start_after, limit } => {
            to_json_binary(&query::get_dpwh_contracts_by_region(deps, region, start_after, limit)?)
        },
        QueryMsg::GetDPWHContractsByStatus { status, start_after, limit } => {
            to_json_binary(&query::get_dpwh_contracts_by_status(deps, status, start_after, limit)?)
        },
        QueryMsg::GetDPWHContractsByYear { infra_year, start_after, limit } => {
            to_json_binary(&query::get_dpwh_contracts_by_year(deps, infra_year, start_after, limit)?)
        },
        QueryMsg::GetDPWHState {} => to_json_binary(&query::get_dpwh_state(deps)?),
        QueryMsg::GetDPWHContractFull { contract_id } => {
            to_json_binary(&query::get_dpwh_contract_full(deps, contract_id)?)
        },
        QueryMsg::GetDPWHComponents { contract_id } => {
            to_json_binary(&query::get_dpwh_components(deps, contract_id)?)
        },
        QueryMsg::GetDPWHBidders { contract_id } => {
            to_json_binary(&query::get_dpwh_bidders(deps, contract_id)?)
        },
        QueryMsg::GetDPWHCoordinates { contract_id } => {
            to_json_binary(&query::get_dpwh_coordinates(deps, contract_id)?)
        },
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        1 => handle_token_instantiate_reply(deps, env, msg),
        _ => Err(ContractError::Std(cosmwasm_std::StdError::generic_err("Unknown reply ID"))),
    }
}

fn handle_token_instantiate_reply(deps: DepsMut, env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.result {
        SubMsgResult::Ok(response) => {
            // Extract the token contract address from the response
            let token_address = response.events
                .iter()
                .find(|e| e.ty == "instantiate")
                .and_then(|e| e.attributes.iter().find(|a| a.key == "_contract_address"))
                .map(|a| a.value.clone())
                .ok_or_else(|| ContractError::Std(cosmwasm_std::StdError::generic_err("Token address not found")))?;

            let token_addr = deps.api.addr_validate(&token_address)?;
            
            // Get the pending GAA ID
            let gaa_id = PENDING_GAA.load(deps.storage)
                .map_err(|_| ContractError::Std(cosmwasm_std::StdError::generic_err("No pending GAA found")))?;
            
            // Load and update the specific GAA
            let mut gaa = GAAS.load(deps.storage, gaa_id.clone())
                .map_err(|_| ContractError::NotFound { entity: "GAA".to_string() })?;
            
            // Update the GAA with the token address
            gaa.token_address = Some(token_addr.clone());
            GAAS.save(deps.storage, gaa_id.clone(), &gaa)?;
            
            // Store token info for queries
            let token_info = TokenInfo {
                gaa_id: gaa_id.clone(),
                token_address: token_addr.clone(),
                name: format!("GAA {} Peso", gaa.year),
                symbol: format!("GAA{}", year_to_roman(gaa.year)), // Use Roman numeral encoding
                decimals: 6,
                total_supply: gaa.total_amount,
            };
            TOKEN_INFO.save(deps.storage, gaa_id.clone(), &token_info)?;
            
            // Mint the total supply to the GAA contract so it can distribute tokens
            let mint_msg = Cw20ExecuteMsg::Mint {
                recipient: env.contract.address.to_string(), // Mint to this contract
                amount: gaa.total_amount,
            };
            
            let mint_cosmos_msg = CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: token_addr.to_string(),
                msg: to_json_binary(&mint_msg)?,
                funds: vec![],
            });
            
            // Clear the pending GAA
            PENDING_GAA.remove(deps.storage);
            
            Ok(Response::new()
                .add_message(mint_cosmos_msg)
                .add_attribute("action", "token_instantiated")
                .add_attribute("token_address", token_address)
                .add_attribute("gaa_id", gaa_id)
                .add_attribute("minted_amount", gaa.total_amount.to_string()))
        }
        SubMsgResult::Err(err) => Err(ContractError::Std(cosmwasm_std::StdError::generic_err(format!("Token instantiation failed: {}", err)))),
    }
}

pub mod query {
    use super::*;

    pub fn count(deps: Deps) -> StdResult<GetCountResponse> {
        let state = STATE.load(deps.storage)?;
        Ok(GetCountResponse { count: state.count })
    }

    pub fn get_gaa(deps: Deps, id: String) -> StdResult<GAA> {
        GAAS.load(deps.storage, id)
    }

    pub fn get_gaas(deps: Deps, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedGAAsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        // Fetch limit + 1 to check if there are more items
        let gaas: Vec<GAA> = GAAS
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, gaa)| gaa))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = gaas.len() > limit;
        let gaas: Vec<GAA> = gaas.into_iter().take(limit).collect();
        let count = gaas.len() as u32;
        
        let total = GAAS
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;
        
        Ok(PaginatedGAAsResponse { gaas, total, count, has_more })
    }

    pub fn get_gaa_by_year(deps: Deps, year: u32, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedGAAsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        // Query the year index to get GAA IDs, then load the full GAA objects
        let gaa_ids: Vec<String> = GAAS_BY_YEAR
            .prefix(year)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(gaa_id, _)| gaa_id))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = gaa_ids.len() > limit;
        let gaa_ids: Vec<String> = gaa_ids.into_iter().take(limit).collect();
        
        // Load full GAA objects
        let gaas: Vec<GAA> = gaa_ids
            .into_iter()
            .map(|id| GAAS.load(deps.storage, id))
            .collect::<StdResult<Vec<_>>>()?;
        
        let count = gaas.len() as u32;
        
        // Count total GAAs for this year
        let total = GAAS_BY_YEAR
            .prefix(year)
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;
        
        Ok(PaginatedGAAsResponse { gaas, total, count, has_more })
    }

    pub fn get_pap(deps: Deps, gaa_id: String, pap_id: String) -> StdResult<PAP> {
        PAPS.load(deps.storage, (gaa_id, pap_id))
    }

    pub fn get_paps_by_gaa(deps: Deps, gaa_id: String, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedPAPsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|pap_id| Bound::exclusive(pap_id));
        
        let paps: Vec<PAP> = PAPS
            .prefix(gaa_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, pap)| pap))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = paps.len() > limit;
        let paps: Vec<PAP> = paps.into_iter().take(limit).collect();
        let count = paps.len() as u32;
        
        // Use cached pap_count from GAA instead of iterating through all PAPs
        let gaa = GAAS.load(deps.storage, gaa_id)?;
        let total = gaa.pap_count;
        
        Ok(PaginatedPAPsResponse { paps, total, count, has_more })
    }

    pub fn get_paps_by_gaa_num_idx(deps: Deps, gaa_id: String, start_idx: Option<u32>, limit: Option<u32>) -> StdResult<PaginatedPAPsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_idx.map(|idx| Bound::inclusive(idx));
        
        // Query PAPS_BY_IDX to get pap_ids in order by idx
        let pap_ids: Vec<String> = PAPS_BY_IDX
            .prefix(gaa_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, pap_id)| pap_id))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = pap_ids.len() > limit;
        let pap_ids: Vec<String> = pap_ids.into_iter().take(limit).collect();
        
        // Load full PAP records
        let mut paps: Vec<PAP> = Vec::with_capacity(pap_ids.len());
        for pap_id in pap_ids {
            let pap = PAPS.load(deps.storage, (gaa_id.clone(), pap_id))?;
            paps.push(pap);
        }
        
        let count = paps.len() as u32;
        
        // Use cached pap_count from GAA
        let gaa = GAAS.load(deps.storage, gaa_id)?;
        let total = gaa.pap_count;
        
        Ok(PaginatedPAPsResponse { paps, total, count, has_more })
    }

    pub fn get_pap_by_composite_key(deps: Deps, composite_key_hash: String) -> StdResult<PAP> {
        // Look up pap_id from composite key hash index
        let pap_id = PAPS_BY_COMPOSITE_KEY.load(deps.storage, composite_key_hash)
            .map_err(|_| cosmwasm_std::StdError::not_found("PAP with composite key hash"))?;
        
        // Find the PAP by iterating (we need gaa_id to load with composite key)
        let pap = PAPS
            .range(deps.storage, None, None, Order::Ascending)
            .find(|item| {
                if let Ok((key, _)) = item {
                    key.1 == pap_id
                } else {
                    false
                }
            })
            .ok_or_else(|| cosmwasm_std::StdError::not_found("PAP"))?
            .map(|(_, pap)| pap)?;
        
        Ok(pap)
    }

    pub fn get_saro(deps: Deps, pap_id: String, saro_id: String) -> StdResult<SARO> {
        SAROS.load(deps.storage, (pap_id, saro_id))
    }

    pub fn get_saros_by_pap(deps: Deps, pap_id: String, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedSAROsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|saro_id| Bound::exclusive(saro_id));
        
        let saros: Vec<SARO> = SAROS
            .prefix(pap_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, saro)| saro))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = saros.len() > limit;
        let saros: Vec<SARO> = saros.into_iter().take(limit).collect();
        let count = saros.len() as u32;
        
        let total = SAROS
            .prefix(pap_id)
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;
        
        Ok(PaginatedSAROsResponse { saros, total, count, has_more })
    }

    pub fn get_nca(deps: Deps, nca_id: String) -> StdResult<NCA> {
        NCAS_BY_ID.load(deps.storage, nca_id)
    }

    pub fn get_obligations_by_saro(deps: Deps, saro_id: String, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedObligationsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|obligation_id| Bound::exclusive(obligation_id));
        
        let obligations: Vec<Obligation> = OBLIGATIONS
            .prefix(saro_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, obligation)| obligation))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = obligations.len() > limit;
        let obligations: Vec<Obligation> = obligations.into_iter().take(limit).collect();
        let count = obligations.len() as u32;
        
        let total = OBLIGATIONS
            .prefix(saro_id)
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;
        
        Ok(PaginatedObligationsResponse { obligations, total, count, has_more })
    }

    pub fn get_obligation(deps: Deps, saro_id: String, obligation_id: String) -> StdResult<Obligation> {
        OBLIGATIONS.load(deps.storage, (saro_id, obligation_id))
    }

    pub fn get_ncas_by_saro(deps: Deps, saro_id: String, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedNCAsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|nca_id| Bound::exclusive((saro_id.clone(), nca_id)));

        // First, page over the (saro_id, nca_id) index entries
        let index_entries: Vec<(String, String)> = NCAS_BY_SARO
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(key, _)| key))
            .collect::<StdResult<Vec<_>>>()?;

        let has_more = index_entries.len() > limit;

        // Resolve NCA records by ID
        let mut ncas: Vec<NCA> = Vec::new();
        for (idx_saro_id, nca_id) in index_entries.into_iter().take(limit) {
            // Extra safety: ensure we're only returning rows for the requested SARO
            if idx_saro_id == saro_id {
                let nca = NCAS_BY_ID.load(deps.storage, nca_id)?;
                ncas.push(nca);
            }
        }

        let count = ncas.len() as u32;

        // Total count for this SARO: scan the full index for this SARO only
        let total = NCAS_BY_SARO
            .prefix(saro_id)
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;

        Ok(PaginatedNCAsResponse { ncas, total, count, has_more })
    }

    pub fn get_disbursement_voucher(deps: Deps, obligation_id: String, nca_id: String, dv_id: String) -> StdResult<DisbursementVoucher> {
        DISBURSEMENT_VOUCHERS.load(deps.storage, (obligation_id, nca_id, dv_id))
    }

    pub fn get_disbursement_vouchers_by_obligation(deps: Deps, obligation_id: String, start_after: Option<(String, String)>, limit: Option<u32>) -> StdResult<PaginatedDisbursementVouchersResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        
        // DVs have 3-tuple key (obligation_id, nca_id, dv_id)
        // Scan all and filter by obligation_id (1st element)
        let start = start_after.map(|(nca_id, dv_id)| Bound::exclusive((obligation_id.clone(), nca_id, dv_id)));
        
        let disbursement_vouchers: Vec<DisbursementVoucher> = DISBURSEMENT_VOUCHERS
            .range(deps.storage, start, None, Order::Ascending)
            .filter(|item| {
                if let Ok((key, _)) = item {
                    key.0 == obligation_id
                } else {
                    false
                }
            })
            .take(limit + 1)
            .map(|item| item.map(|(_, dv)| dv))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = disbursement_vouchers.len() > limit;
        let disbursement_vouchers: Vec<DisbursementVoucher> = disbursement_vouchers.into_iter().take(limit).collect();
        let count = disbursement_vouchers.len() as u32;
        
        let total = DISBURSEMENT_VOUCHERS
            .range(deps.storage, None, None, Order::Ascending)
            .filter(|item| {
                if let Ok((key, _)) = item {
                    key.0 == obligation_id
                } else {
                    false
                }
            })
            .count() as u32;
        
        Ok(PaginatedDisbursementVouchersResponse { disbursement_vouchers, total, count, has_more })
    }

    pub fn get_disbursement_vouchers_by_nca(deps: Deps, nca_id: String, start_after: Option<(String, String)>, limit: Option<u32>) -> StdResult<PaginatedDisbursementVouchersResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        
        // DVs have 3-tuple key (obligation_id, nca_id, dv_id)
        // To query by nca_id (2nd element), we need to scan and filter
        let start = start_after.map(|(obl_id, dv_id)| Bound::exclusive((obl_id, nca_id.clone(), dv_id)));
        
        let disbursement_vouchers: Vec<DisbursementVoucher> = DISBURSEMENT_VOUCHERS
            .range(deps.storage, start, None, Order::Ascending)
            .filter(|item| {
                if let Ok((key, _)) = item {
                    key.1 == nca_id
                } else {
                    false
                }
            })
            .take(limit + 1)
            .map(|item| item.map(|(_, dv)| dv))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = disbursement_vouchers.len() > limit;
        let disbursement_vouchers: Vec<DisbursementVoucher> = disbursement_vouchers.into_iter().take(limit).collect();
        let count = disbursement_vouchers.len() as u32;
        
        // Count total DVs for this NCA
        let total = DISBURSEMENT_VOUCHERS
            .range(deps.storage, None, None, Order::Ascending)
            .filter(|item| {
                if let Ok((key, _)) = item {
                    key.1 == nca_id
                } else {
                    false
                }
            })
            .count() as u32;
        
        Ok(PaginatedDisbursementVouchersResponse { disbursement_vouchers, total, count, has_more })
    }

    pub fn get_budget_hierarchy(
        deps: Deps,
        gaa_id: String,
        pap_start_after: Option<String>,
        paps_per_page: Option<u32>,
        saros_per_pap: Option<u32>,
        ncas_per_saro: Option<u32>,
        obligations_per_saro: Option<u32>,
        dvs_per_parent: Option<u32>,
        disbursements_per_dv: Option<u32>,
    ) -> StdResult<BudgetHierarchyResponse> {
        let gaa = GAAS.load(deps.storage, gaa_id.clone())?;
        
        // Use provided limits or defaults (max 1000 per level)
        let paps_limit = paps_per_page.unwrap_or(100).min(1000);
        let saros_limit = saros_per_pap.unwrap_or(100).min(1000);
        let ncas_limit = ncas_per_saro.unwrap_or(100).min(1000);
        let obligations_limit = obligations_per_saro.unwrap_or(100).min(1000);
        let dvs_limit = dvs_per_parent.unwrap_or(100).min(1000);
        let disbursements_limit = disbursements_per_dv.unwrap_or(100).min(1000);
        
        // Efficient cursor-based pagination (O(limit))
        let start = pap_start_after.map(|start_after_id| Bound::exclusive(start_after_id));
        
        let paps: Vec<PAP> = PAPS
            .prefix(gaa_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(paps_limit as usize)
            .map(|item| item.map(|(_, pap)| pap))
            .collect::<StdResult<Vec<_>>>()?;
        
        let mut paps_with_children = Vec::new();
        for pap in paps {
            // Load SAROs for this PAP with specified limit
            let saros_response = get_saros_by_pap(deps, pap.id.clone(), None, Some(saros_limit))?;
            let mut saros_with_children = Vec::new();
            
            for saro in saros_response.saros {
                // Load Obligations and NCAs for this SARO with specified limits
                let obligations_response = get_obligations_by_saro(deps, saro.id.clone(), None, Some(obligations_limit))?;
                let ncas_response = get_ncas_by_saro(deps, saro.id.clone(), None, Some(ncas_limit))?;
                
                // Build obligations with their DisbursementVouchers
                let mut obligations_with_children = Vec::new();
                for obligation in obligations_response.obligations {
                    let dvs_response = get_disbursement_vouchers_by_obligation(
                        deps, 
                        obligation.id.clone(), 
                        None, 
                        Some(dvs_limit)
                    )?;
                    
                    obligations_with_children.push(ObligationWithChildren {
                        obligation,
                        disbursement_vouchers: dvs_response.disbursement_vouchers,
                    });
                }
                
                // Build NCAs with their DisbursementVouchers
                let mut ncas_with_children = Vec::new();
                for nca in ncas_response.ncas {
                    let dvs_response = get_disbursement_vouchers_by_nca(
                        deps, 
                        nca.id.clone(), 
                        None, 
                        Some(dvs_limit)
                    )?;
                    ncas_with_children.push(NCAWithChildren {
                        nca,
                        disbursement_vouchers: dvs_response.disbursement_vouchers,
                    });
                }
                
                saros_with_children.push(SAROWithChildren { 
                    saro, 
                    obligations: obligations_with_children, 
                    ncas: ncas_with_children 
                });
            }
            
            paps_with_children.push(PAPWithChildren { pap, saros: saros_with_children });
        }

        // Use cached pap_count from GAA instead of iterating through all PAPs
        let total_paps = gaa.pap_count;

        Ok(BudgetHierarchyResponse {
            gaa,
            paps: paps_with_children,
            total_paps,
        })
    }

    pub fn get_token_info(deps: Deps, gaa_id: String) -> StdResult<TokenInfo> {
        TOKEN_INFO.load(deps.storage, gaa_id)
    }

    pub fn get_token_balance(deps: Deps, gaa_id: String, address: String) -> StdResult<Uint128> {
        let token_info = TOKEN_INFO.load(deps.storage, gaa_id)?;
        
        // Query the CW20 token contract for balance
        let balance_query = Cw20QueryMsg::Balance { address };
        let balance_response: BalanceResponse = deps.querier.query_wasm_smart(
            token_info.token_address,
            &balance_query,
        )?;
        
        Ok(balance_response.balance)
    }

    pub fn get_disbursement(deps: Deps, dv_id: String, disbursement_id: String) -> StdResult<Disbursement> {
        DISBURSEMENTS.load(deps.storage, (dv_id, disbursement_id))
    }

    pub fn get_disbursements_by_dv(deps: Deps, dv_id: String, start_after: Option<String>, limit: Option<u32>) -> StdResult<PaginatedDisbursementsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|disbursement_id| Bound::exclusive(disbursement_id));
        
        let disbursements: Vec<Disbursement> = DISBURSEMENTS
            .prefix(dv_id.clone())
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, disbursement)| disbursement))
            .collect::<StdResult<Vec<_>>>()?;
        
        let has_more = disbursements.len() > limit;
        let disbursements: Vec<Disbursement> = disbursements.into_iter().take(limit).collect();
        let count = disbursements.len() as u32;
        
        let total = DISBURSEMENTS
            .prefix(dv_id)
            .range(deps.storage, None, None, Order::Ascending)
            .count() as u32;
        
        Ok(PaginatedDisbursementsResponse { disbursements, total, count, has_more })
    }

    // PhilGEPS Procurement Contract queries
    pub fn get_procurement_contract(deps: Deps, id: String) -> StdResult<ProcurementContract> {
        PHILGEPS_CONTRACTS.load(deps.storage, id)
    }

    pub fn get_philgeps_state(deps: Deps) -> StdResult<PhilGEPSState> {
        PHILGEPS_STATE
            .may_load(deps.storage)?
            .ok_or_else(|| cosmwasm_std::StdError::not_found("PhilGEPSState"))
    }

    pub fn get_procurement_contract_by_reference_id(deps: Deps, reference_id: String) -> StdResult<ProcurementContract> {
        // Look up contract_id from reference_id index
        let contract_id = PHILGEPS_CONTRACTS_BY_REF_ID
            .may_load(deps.storage, reference_id.clone())?
            .ok_or_else(|| cosmwasm_std::StdError::not_found(format!("ProcurementContract with reference_id: {}", reference_id)))?;
        
        // Load the actual contract
        PHILGEPS_CONTRACTS.load(deps.storage, contract_id)
    }

    pub fn get_procurement_contract_by_contract_no(deps: Deps, contract_no: String) -> StdResult<ProcurementContract> {
        // Look up contract_id from contract_no index
        let contract_id = PHILGEPS_CONTRACTS_BY_CONTRACT_NO
            .may_load(deps.storage, contract_no.clone())?
            .ok_or_else(|| cosmwasm_std::StdError::not_found(format!("ProcurementContract with contract_no: {}", contract_no)))?;
        
        // Load the actual contract
        PHILGEPS_CONTRACTS.load(deps.storage, contract_id)
    }

    pub fn get_procurement_contracts(
        deps: Deps,
        start_after: Option<String>,
        limit: Option<u32>,
        organization_name: Option<String>,
        awardee_name: Option<String>,
        business_category: Option<String>,
    ) -> StdResult<PaginatedProcurementContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        // Get total from state for efficiency
        let total = PHILGEPS_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        // Get all contracts with pagination
        let all_contracts: Vec<ProcurementContract> = PHILGEPS_CONTRACTS
            .range(deps.storage, start, None, Order::Ascending)
            .filter_map(|item| {
                match item {
                    Ok((_, contract)) => {
                        // Apply filters
                        let org_match = organization_name.as_ref().map_or(true, |org| {
                            contract.organization_name.as_ref().map_or(false, |c| c.to_lowercase().contains(&org.to_lowercase()))
                        });
                        let awardee_match = awardee_name.as_ref().map_or(true, |awardee| {
                            contract.awardee_name.as_ref().map_or(false, |c| c.to_lowercase().contains(&awardee.to_lowercase()))
                        });
                        let category_match = business_category.as_ref().map_or(true, |cat| {
                            contract.business_category.as_ref().map_or(false, |c| c.to_lowercase().contains(&cat.to_lowercase()))
                        });
                        
                        if org_match && awardee_match && category_match {
                            Some(contract)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            })
            .take(limit + 1)
            .collect();
        
        let has_more = all_contracts.len() > limit;
        let contracts: Vec<ProcurementContract> = all_contracts.into_iter().take(limit).collect();
        let count = contracts.len() as u32;
        
        Ok(PaginatedProcurementContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_procurement_contracts_by_num_idx(
        deps: Deps,
        start_idx: Option<u32>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedProcurementContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start_idx = start_idx.unwrap_or(0);
        
        // Get total from state for efficiency
        let total = PHILGEPS_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        // Collect contracts by numeric index
        let mut contracts: Vec<ProcurementContract> = Vec::new();
        let mut current_idx = start_idx;
        
        while contracts.len() < limit + 1 && current_idx < total {
            if let Some(contract_id) = PHILGEPS_CONTRACTS_BY_IDX.may_load(deps.storage, current_idx)? {
                if let Ok(contract) = PHILGEPS_CONTRACTS.load(deps.storage, contract_id) {
                    contracts.push(contract);
                }
            }
            current_idx += 1;
        }
        
        let has_more = contracts.len() > limit;
        let contracts: Vec<ProcurementContract> = contracts.into_iter().take(limit).collect();
        let count = contracts.len() as u32;
        
        Ok(PaginatedProcurementContractsResponse { contracts, total, count, has_more })
    }

    // DPWH Query functions
    pub fn get_dpwh_contract(deps: Deps, contract_id: String) -> StdResult<DPWHContract> {
        DPWH_CONTRACTS.load(deps.storage, contract_id)
    }

    pub fn get_dpwh_state(deps: Deps) -> StdResult<DPWHState> {
        DPWH_STATE.may_load(deps.storage)?.ok_or_else(|| {
            cosmwasm_std::StdError::not_found("DPWHState")
        })
    }

    pub fn get_dpwh_contracts(
        deps: Deps,
        start_after: Option<String>,
        limit: Option<u32>,
        region: Option<String>,
        status: Option<String>,
        infra_year: Option<String>,
    ) -> StdResult<PaginatedDPWHContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        let total = DPWH_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        let all_contracts: Vec<DPWHContract> = DPWH_CONTRACTS
            .range(deps.storage, start, None, Order::Ascending)
            .filter_map(|item| {
                match item {
                    Ok((_, contract)) => {
                        let region_match = region.as_ref().map_or(true, |r| {
                            contract.region.as_ref().map_or(false, |c| c == r)
                        });
                        let status_match = status.as_ref().map_or(true, |s| {
                            contract.status.as_ref().map_or(false, |c| c == s)
                        });
                        let year_match = infra_year.as_ref().map_or(true, |y| {
                            contract.infra_year.as_ref().map_or(false, |c| c == y)
                        });
                        
                        if region_match && status_match && year_match {
                            Some(contract)
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                }
            })
            .take(limit + 1)
            .collect();
        
        let has_more = all_contracts.len() > limit;
        let contracts: Vec<DPWHContract> = all_contracts.into_iter().take(limit).collect();
        let count = contracts.len() as u32;
        
        Ok(PaginatedDPWHContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_dpwh_contracts_by_num_idx(
        deps: Deps,
        start_idx: Option<u32>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedDPWHContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start_idx = start_idx.unwrap_or(0);
        
        let total = DPWH_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        let mut contracts: Vec<DPWHContract> = Vec::new();
        let mut current_idx = start_idx;
        
        while contracts.len() < limit + 1 && current_idx < total {
            if let Some(contract_id) = DPWH_CONTRACTS_BY_IDX.may_load(deps.storage, current_idx)? {
                if let Ok(contract) = DPWH_CONTRACTS.load(deps.storage, contract_id) {
                    contracts.push(contract);
                }
            }
            current_idx += 1;
        }
        
        let has_more = contracts.len() > limit;
        let contracts: Vec<DPWHContract> = contracts.into_iter().take(limit).collect();
        let count = contracts.len() as u32;
        
        Ok(PaginatedDPWHContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_dpwh_contracts_by_region(
        deps: Deps,
        region: String,
        start_after: Option<String>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedDPWHContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        let total = DPWH_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        let contract_ids: Vec<String> = DPWH_CONTRACTS_BY_REGION
            .prefix(region)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .filter_map(|item| item.ok().map(|(id, _)| id))
            .collect();
        
        let has_more = contract_ids.len() > limit;
        let contract_ids: Vec<String> = contract_ids.into_iter().take(limit).collect();
        
        let contracts: Vec<DPWHContract> = contract_ids
            .into_iter()
            .filter_map(|id| DPWH_CONTRACTS.load(deps.storage, id).ok())
            .collect();
        
        let count = contracts.len() as u32;
        
        Ok(PaginatedDPWHContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_dpwh_contracts_by_status(
        deps: Deps,
        status: String,
        start_after: Option<String>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedDPWHContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        let total = DPWH_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        let contract_ids: Vec<String> = DPWH_CONTRACTS_BY_STATUS
            .prefix(status)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .filter_map(|item| item.ok().map(|(id, _)| id))
            .collect();
        
        let has_more = contract_ids.len() > limit;
        let contract_ids: Vec<String> = contract_ids.into_iter().take(limit).collect();
        
        let contracts: Vec<DPWHContract> = contract_ids
            .into_iter()
            .filter_map(|id| DPWH_CONTRACTS.load(deps.storage, id).ok())
            .collect();
        
        let count = contracts.len() as u32;
        
        Ok(PaginatedDPWHContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_dpwh_contracts_by_year(
        deps: Deps,
        infra_year: String,
        start_after: Option<String>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedDPWHContractsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(|id| Bound::exclusive(id));
        
        let total = DPWH_STATE
            .may_load(deps.storage)?
            .map(|s| s.contract_count)
            .unwrap_or(0);
        
        let contract_ids: Vec<String> = DPWH_CONTRACTS_BY_YEAR
            .prefix(infra_year)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .filter_map(|item| item.ok().map(|(id, _)| id))
            .collect();
        
        let has_more = contract_ids.len() > limit;
        let contract_ids: Vec<String> = contract_ids.into_iter().take(limit).collect();
        
        let contracts: Vec<DPWHContract> = contract_ids
            .into_iter()
            .filter_map(|id| DPWH_CONTRACTS.load(deps.storage, id).ok())
            .collect();
        
        let count = contracts.len() as u32;
        
        Ok(PaginatedDPWHContractsResponse { contracts, total, count, has_more })
    }

    pub fn get_dpwh_contract_full(deps: Deps, contract_id: String) -> StdResult<DPWHContractWithChildren> {
        let contract = DPWH_CONTRACTS.load(deps.storage, contract_id.clone())?;
        
        let components: Vec<DPWHComponent> = DPWH_COMPONENTS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, c)| c))
            .collect();
        
        let bidders: Vec<DPWHBidder> = DPWH_BIDDERS
            .prefix(contract_id.clone())
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, b)| b))
            .collect();
        
        let coordinates: Vec<DPWHCoordinate> = DPWH_COORDINATES
            .prefix(contract_id)
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, c)| c))
            .collect();
        
        Ok(DPWHContractWithChildren {
            contract,
            components,
            bidders,
            coordinates,
        })
    }

    pub fn get_dpwh_components(deps: Deps, contract_id: String) -> StdResult<Vec<DPWHComponent>> {
        let components: Vec<DPWHComponent> = DPWH_COMPONENTS
            .prefix(contract_id)
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, c)| c))
            .collect();
        Ok(components)
    }

    pub fn get_dpwh_bidders(deps: Deps, contract_id: String) -> StdResult<Vec<DPWHBidder>> {
        let bidders: Vec<DPWHBidder> = DPWH_BIDDERS
            .prefix(contract_id)
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, b)| b))
            .collect();
        Ok(bidders)
    }

    pub fn get_dpwh_coordinates(deps: Deps, contract_id: String) -> StdResult<Vec<DPWHCoordinate>> {
        let coordinates: Vec<DPWHCoordinate> = DPWH_COORDINATES
            .prefix(contract_id)
            .range(deps.storage, None, None, Order::Ascending)
            .filter_map(|item| item.ok().map(|(_, c)| c))
            .collect();
        Ok(coordinates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_json};
    
    // Helper macro to create PAP with minimal fields
    macro_rules! create_pap {
        ($id:expr, $gaa_id:expr, $desc:expr, $amount:expr $(,)?) => {
            ExecuteMsg::CreatePAP {
                id: $id,
                gaa_id: $gaa_id,
                sorder: None,
                department: None,
                uacs_dpt_dsc: None,
                agency: None,
                uacs_agy_dsc: None,
                prexc_fpap_id: None,
                prexc_level: None,
                dsc: None,
                oper_unit: None,
                uacs_oper_dsc: None,
                uacs_reg_id: None,
                uacs_operdiv_id: None,
                uacs_div_dsc: None,
                fund_cd: None,
                uacs_fundsubcat_dsc: None,
                uacs_exp_cd: None,
                uacs_exp_dsc: None,
                uacs_sobj_cd: None,
                uacs_sobj_dsc: $desc,
                amount: $amount,
            }
        };
    }

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_json(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Increment {};
        let _res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // should increase counter by 1
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_json(&res).unwrap();
        assert_eq!(18, value.count);
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let unauth_info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_info = mock_info("creator", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();

        // should now be 5
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_json(&res).unwrap();
        assert_eq!(5, value.count);
    }

    #[test]
    fn test_budget_hierarchy() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create GAA
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(5_450_000_000_000u128), // 5.45 trillion pesos
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1, // Mock CW20 code ID for tests
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        // Create PAP under GAA
        let create_pap_msg = ExecuteMsg::CreatePAP {
            id: "pap_dpwh_001".to_string(),
            gaa_id: "gaa_2024".to_string(),
            sorder: None,
            department: None,
            uacs_dpt_dsc: Some("Department of Public Works and Highways".to_string()),
            agency: None,
            uacs_agy_dsc: None,
            prexc_fpap_id: None,
            prexc_level: None,
            dsc: None,
            oper_unit: None,
            uacs_oper_dsc: None,
            uacs_reg_id: None,
            uacs_operdiv_id: None,
            uacs_div_dsc: None,
            fund_cd: None,
            uacs_fundsubcat_dsc: None,
            uacs_exp_cd: None,
            uacs_exp_dsc: None,
            uacs_sobj_cd: None,
            uacs_sobj_dsc: "Infrastructure Development Program".to_string(),
            amount: Uint128::new(1_000_000_000_000u128), // 1 trillion pesos
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

        // Create SARO under PAP
        let create_saro_msg = ExecuteMsg::CreateSARO {
            id: "saro_001".to_string(),
            pap_id: "pap_dpwh_001".to_string(),
            saro_number: "SARO-BMB-A-24-0001".to_string(),
            amount: Uint128::new(500_000_000_000u128), // 500 billion pesos
            release_date: Some("2024-01-15".to_string()),
            department: Some("DPWH".to_string()),
            agency: Some("Department of Public Works and Highways".to_string()),
            operating_unit: None,
            purpose: Some("Infrastructure development".to_string()),
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

        // Query GAA
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetGAA { id: "gaa_2024".to_string() }).unwrap();
        let gaa: GAA = from_json(&res).unwrap();
        assert_eq!(gaa.year, 2024);
        assert_eq!(gaa.total_amount, Uint128::new(5_450_000_000_000u128));

        // Query PAPs by GAA
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetPAPsByGAA { 
            gaa_id: "gaa_2024".to_string(),
            start_after: None,
            limit: None,
        }).unwrap();
        let paps_response: PaginatedPAPsResponse = from_json(&res).unwrap();
        assert_eq!(paps_response.paps.len(), 1);
        assert_eq!(paps_response.total, 1);
        assert_eq!(paps_response.paps[0].uacs_sobj_dsc, "Infrastructure Development Program".to_string());

        // Query SAROs by PAP
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetSAROsByPAP { 
            pap_id: "pap_dpwh_001".to_string(),
            start_after: None,
            limit: None,
        }).unwrap();
        let saros_response: PaginatedSAROsResponse = from_json(&res).unwrap();
        assert_eq!(saros_response.saros.len(), 1);
        assert_eq!(saros_response.total, 1);
        assert_eq!(saros_response.saros[0].saro_number, "SARO-BMB-A-24-0001");

        // Query complete hierarchy
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetBudgetHierarchy { 
            gaa_id: "gaa_2024".to_string(),
            pap_start_after: None,
            paps_per_page: None,
            saros_per_pap: None,
            ncas_per_saro: None,
            obligations_per_saro: None,
            dvs_per_parent: None,
            disbursements_per_dv: None,
        }).unwrap();
        let hierarchy: BudgetHierarchyResponse = from_json(&res).unwrap();
        assert_eq!(hierarchy.gaa.year, 2024);
        assert_eq!(hierarchy.paps.len(), 1);
        assert_eq!(hierarchy.total_paps, 1);
        assert_eq!(hierarchy.paps[0].saros.len(), 1);
    }

    #[test]
    fn test_pap_exceeds_gaa_balance() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create GAA with 1 trillion pesos
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(1_000_000_000_000u128), // 1 trillion pesos
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        // Try to create PAP that exceeds GAA balance (2 trillion > 1 trillion)
        let create_pap_msg = create_pap!(
            "pap_oversized".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(2_000_000_000_000u128) // 2 trillion pesos - exceeds GAA
        );
        
        let res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Insufficient GAA balance"));
    }

    #[test]
    fn test_multiple_allocations_exhaust_balance() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create GAA with 1 trillion pesos
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(1_000_000_000_000u128), // 1 trillion pesos
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        // Create first PAP with 600 billion
        let create_pap1_msg = create_pap!(
            "pap_1".to_string(),
            "gaa_2024".to_string(),
            "Test1".to_string(),
            Uint128::new(600_000_000_000u128), // 600 billion pesos
        );
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap1_msg).unwrap();

        // Create second PAP with 300 billion (total now 900 billion, 100 billion remaining)
        let create_pap2_msg = create_pap!(
            "pap_2".to_string(),
            "gaa_2024".to_string(),
            "Test2".to_string(),
            Uint128::new(300_000_000_000u128), // 300 billion pesos
        );
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap2_msg).unwrap();

        // Try to create third PAP with 200 billion (would exceed remaining 100 billion)
        let create_pap3_msg = create_pap!(
            "pap_3".to_string(),
            "gaa_2024".to_string(),
            "Test3".to_string(),
            Uint128::new(200_000_000_000u128), // 200 billion - exceeds remaining 100 billion
        );
        
        let res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap3_msg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Insufficient GAA balance"));

        // Verify GAA available balance is correct (100 billion remaining)
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetGAA { id: "gaa_2024".to_string() }).unwrap();
        let gaa: GAA = from_json(&res).unwrap();
        assert_eq!(gaa.available_amount_for_paps, Uint128::new(100_000_000_000u128)); // 100 billion remaining
    }

    #[test]
    fn test_saro_exceeds_pap_balance() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create GAA
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(1_000_000_000_000u128), // 1 trillion pesos
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        // Create PAP with 500 billion
        let create_pap_msg = create_pap!(
            "pap_limited".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128), // 500 billion pesos
        );
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

        // Try to create SARO that exceeds PAP balance (600 billion > 500 billion)
        let create_saro_msg = ExecuteMsg::CreateSARO {
            id: "saro_oversized".to_string(),
            pap_id: "pap_limited".to_string(),
            saro_number: "SARO-OVERSIZED".to_string(),
            amount: Uint128::new(600_000_000_000u128), // 600 billion - exceeds PAP
            release_date: Some("2024-01-15".to_string()),
            department: None,
            agency: None,
            operating_unit: None,
            purpose: None,
        };
        
        let res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("Insufficient PAP balance"));
    }

    #[test]
    fn test_nca_exceeds_saro_nca_balance_after_obligation() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create GAA -> PAP -> SARO chain
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(1_000_000_000_000u128),
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

        // Create SARO with 300 billion
        let create_saro_msg = ExecuteMsg::CreateSARO {
            id: "saro_limited".to_string(),
            pap_id: "pap_test".to_string(),
            saro_number: "SARO-LIMITED".to_string(),
            amount: Uint128::new(300_000_000_000u128), // 300 billion
            release_date: Some("2024-01-15".to_string()),
            department: None,
            agency: None,
            operating_unit: None,
            purpose: None,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

        // First create an Obligation under the SARO
        let create_obligation_msg = ExecuteMsg::CreateObligation {
            id: "obl_limited".to_string(),
            saro_id: "saro_limited".to_string(),
            obligation_number: "OBL-LIMITED".to_string(),
            amount: Uint128::new(250_000_000_000u128), // 250 billion
            description: Some("Test obligation".to_string()),
            payee: Some("Test payee".to_string()),
            obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

        // Create NCA referencing the SARO (chain no longer enforces SARO->NCA balance)
        let create_nca_msg = ExecuteMsg::CreateNCA {
            id: "nca_oversized".to_string(),
            saro_ids: vec!["saro_limited".to_string()],
            nca_number: "NCA-OVERSIZED".to_string(),
            amount: Uint128::new(400_000_000_000u128), // 400 billion - exceeds SARO
            approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
            issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
            release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
            department: None,
            agency: None,
            operating_unit: None,
            purpose: None,
            cancel_remarks: None,
            release_type_cd: Some("REGULAR".to_string()),
        };
        
        let res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg);
        // Under Option C, SARO balances are not enforced for NCAs, so this should succeed
        assert!(res.is_ok());
    }

    #[test]
    fn test_nca_exceeds_saro_balance() {
        use cosmwasm_std::Uint128;
        
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg { count: 0 };
        let info = mock_info("creator123", &coins(1000, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Create complete chain: GAA -> PAP -> SARO -> NCA
        let create_gaa_msg = ExecuteMsg::CreateGAA {
            id: "gaa_2024".to_string(),
            year: 2024,
            total_amount: Uint128::new(1_000_000_000_000u128),
            status: "Active".to_string(),
            token_name: "GAA 2024 Peso".to_string(),
            token_symbol: "GAAPESO".to_string(),
            token_decimals: 6,
            cw20_code_id: 1,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

        let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

        let create_saro_msg = ExecuteMsg::CreateSARO {
            id: "saro_test".to_string(),
            pap_id: "pap_test".to_string(),
            saro_number: "SARO-TEST".to_string(),
            amount: Uint128::new(300_000_000_000u128),
            release_date: Some("2024-01-15".to_string()),
            department: None,
            agency: None,
            operating_unit: None,
            purpose: None,
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

        // Create Obligation with 200 billion
        let create_obligation_msg = ExecuteMsg::CreateObligation {
            id: "obl_limited".to_string(),
            saro_id: "saro_test".to_string(),
            obligation_number: "OBL-LIMITED".to_string(),
            amount: Uint128::new(200_000_000_000u128), // 200 billion
            description: Some("Test obligation".to_string()),
            payee: Some("Test Corp".to_string()),
            obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
        };
        let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

        // Create NCA referencing the SARO (chain no longer enforces SARO->NCA balance)
        let create_nca_msg = ExecuteMsg::CreateNCA {
            id: "nca_oversized".to_string(),
            saro_ids: vec!["saro_test".to_string()],
            nca_number: "NCA-OVERSIZED".to_string(),
            amount: Uint128::new(400_000_000_000u128), // 400 billion - exceeds SARO
            approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
            issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
            release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
            department: None,
            agency: None,
            operating_unit: None,
            purpose: None,
            cancel_remarks: None,
            release_type_cd: Some("REGULAR".to_string()),
        };
        
        let res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg);
        // Under Option C, SARO balances are not enforced for NCAs, so this should succeed
        assert!(res.is_ok());
    }

#[test]
fn test_nca_exceeds_saro_nca_balance() {
    use cosmwasm_std::Uint128;
    
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg { count: 0 };
    let info = mock_info("creator123", &coins(1000, "token"));
    let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Create complete chain: GAA -> PAP -> SARO -> Obligation
    let create_gaa_msg = ExecuteMsg::CreateGAA {
        id: "gaa_2024".to_string(),
        year: 2024,
        total_amount: Uint128::new(1_000_000_000_000u128),
        status: "Active".to_string(),
        token_name: "GAA 2024 Peso".to_string(),
        token_symbol: "GAAPESO".to_string(),
        token_decimals: 6,
        cw20_code_id: 1,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

    let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

    let create_saro_msg = ExecuteMsg::CreateSARO {
        id: "saro_test".to_string(),
        pap_id: "pap_test".to_string(),
        saro_number: "SARO-TEST".to_string(),
        amount: Uint128::new(300_000_000_000u128),
        release_date: Some("2024-01-15".to_string()),
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

    // Create Obligation with 200 billion
    let create_obligation_msg = ExecuteMsg::CreateObligation {
        id: "obl_limited".to_string(),
        saro_id: "saro_test".to_string(),
        obligation_number: "OBL-LIMITED".to_string(),
        amount: Uint128::new(200_000_000_000u128), // 200 billion
        description: Some("Test obligation".to_string()),
        payee: Some("Test Corp".to_string()),
        obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

    // Create NCA referencing the SARO (chain no longer enforces SARO->NCA balance)
    let create_nca_msg = ExecuteMsg::CreateNCA {
        id: "nca_oversized".to_string(),
        saro_ids: vec!["saro_test".to_string()],
        nca_number: "NCA-OVERSIZED".to_string(),
        amount: Uint128::new(400_000_000_000u128), // 400 billion - exceeds SARO
        approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
        issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
        release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
        cancel_remarks: None,
        release_type_cd: Some("REGULAR".to_string()),
    };
    
    let res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg);
    // Under Option C, SARO balances are not enforced for NCAs, so this should succeed
    assert!(res.is_ok());
}

#[test]
fn test_disbursement_voucher_creation_and_balance_deduction() {
    use cosmwasm_std::Uint128;
    
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg { count: 0 };
    let info = mock_info("creator123", &coins(1000, "token"));
    let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Create complete chain: GAA -> PAP -> SARO -> Obligation and NCA
    let create_gaa_msg = ExecuteMsg::CreateGAA {
        id: "gaa_2024".to_string(),
        year: 2024,
        total_amount: Uint128::new(1_000_000_000_000u128),
        status: "Active".to_string(),
        token_name: "GAA 2024 Peso".to_string(),
        token_symbol: "GAAPESO".to_string(),
        token_decimals: 6,
        cw20_code_id: 1,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

    let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

    let create_saro_msg = ExecuteMsg::CreateSARO {
        id: "saro_test".to_string(),
        pap_id: "pap_test".to_string(),
        saro_number: "SARO-TEST".to_string(),
        amount: Uint128::new(300_000_000_000u128),
        release_date: Some("2024-01-15".to_string()),
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

    // Create Obligation with 200 billion
    let create_obligation_msg = ExecuteMsg::CreateObligation {
        id: "obl_test".to_string(),
        saro_id: "saro_test".to_string(),
        obligation_number: "OBL-TEST".to_string(),
        amount: Uint128::new(200_000_000_000u128), // 200 billion
        description: Some("Test obligation".to_string()),
        payee: Some("Test Corp".to_string()),
        obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

    // Create NCA with 150 billion
    let create_nca_msg = ExecuteMsg::CreateNCA {
        id: "nca_test".to_string(),
        saro_ids: vec!["saro_test".to_string()],
        nca_number: "NCA-TEST".to_string(),
        amount: Uint128::new(150_000_000_000u128), // 150 billion
        approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
        issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
        release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
        department: Some("DBM".to_string()),
        agency: Some("Treasury".to_string()),
        operating_unit: Some("Central Office".to_string()),
        purpose: Some("Cash allocation for operations".to_string()),
        cancel_remarks: None,
        release_type_cd: Some("REGULAR".to_string()),
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg).unwrap();

    // Verify initial balances
    let obligation = query::get_obligation(deps.as_ref(), "saro_test".to_string(), "obl_test".to_string()).unwrap();
    let nca = query::get_nca(deps.as_ref(), "nca_test".to_string()).unwrap();
    assert_eq!(obligation.available_amount_for_disbursement_vouchers, Uint128::new(200_000_000_000u128)); // 200 billion
    // No disbursements yet, so nothing has been liquidated from the NCA
    assert_eq!(nca.liquidated_amount_from_disbursements, Uint128::zero());

    // Create DisbursementVoucher with 100 billion (should deduct from both)
    let create_dv_msg = ExecuteMsg::CreateDisbursementVoucher {
        id: "dv_test".to_string(),
        obligation_id: "obl_test".to_string(),
        nca_id: "nca_test".to_string(),
        dv_number: "DV-TEST-001".to_string(),
        amount: Uint128::new(100_000_000_000u128), // 100 billion
        description: Some("Test disbursement".to_string()),
        payee: Some("Test Payee".to_string()),
        disbursement_voucher_date: Some(1709251200),  // 2024-03-01 Unix timestamp
    };
    let res = execute(deps.as_mut(), mock_env(), info.clone(), create_dv_msg).unwrap();

    // Verify DV creation response
    assert_eq!(res.attributes.len(), 4);
    assert_eq!(res.attributes[0].value, "create_disbursement_voucher");
    assert_eq!(res.attributes[1].value, "dv_test");
    assert_eq!(res.attributes[2].value, "obl_test");
    assert_eq!(res.attributes[3].value, "nca_test");

    // Verify DV was created correctly
    let dv = query::get_disbursement_voucher(deps.as_ref(), "obl_test".to_string(), "nca_test".to_string(), "dv_test".to_string()).unwrap();
    assert_eq!(dv.id, "dv_test");
    assert_eq!(dv.obligation_id, "obl_test");
    assert_eq!(dv.nca_id, "nca_test");
    assert_eq!(dv.amount, Uint128::new(100_000_000_000u128));

    // Verify balance was deducted from Obligation only (NCA deduction happens during disbursement)
    let obligation_after = query::get_obligation(deps.as_ref(), "saro_test".to_string(), "obl_test".to_string()).unwrap();
    let nca_after = query::get_nca(deps.as_ref(), "nca_test".to_string()).unwrap();

    assert_eq!(obligation_after.available_amount_for_disbursement_vouchers, Uint128::new(100_000_000_000u128)); // 100 billion remaining
    // Still no disbursements; NCA liquidated amount remains zero
    assert_eq!(nca_after.liquidated_amount_from_disbursements, Uint128::zero());

    // Verify DV can be queried by both parents
    let dvs_by_obligation = query::get_disbursement_vouchers_by_obligation(deps.as_ref(), "obl_test".to_string(), None, None).unwrap();
    let dvs_by_nca = query::get_disbursement_vouchers_by_nca(deps.as_ref(), "nca_test".to_string(), None, None).unwrap();
    
    assert_eq!(dvs_by_obligation.disbursement_vouchers.len(), 1);
    assert_eq!(dvs_by_nca.disbursement_vouchers.len(), 1);
    assert_eq!(dvs_by_obligation.disbursement_vouchers[0].id, "dv_test");
    assert_eq!(dvs_by_nca.disbursement_vouchers[0].id, "dv_test");
}

#[test]
fn test_disbursement_voucher_exceeds_obligation_balance() {
    use cosmwasm_std::Uint128;
    
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg { count: 0 };
    let info = mock_info("creator123", &coins(1000, "token"));
    let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Create complete chain: GAA -> PAP -> SARO -> Obligation and NCA
    let create_gaa_msg = ExecuteMsg::CreateGAA {
        id: "gaa_2024".to_string(),
        year: 2024,
        total_amount: Uint128::new(1_000_000_000_000u128),
        status: "Active".to_string(),
        token_name: "GAA 2024 Peso".to_string(),
        token_symbol: "GAAPESO".to_string(),
        token_decimals: 6,
        cw20_code_id: 1,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

    let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

    let create_saro_msg = ExecuteMsg::CreateSARO {
        id: "saro_test".to_string(),
        pap_id: "pap_test".to_string(),
        saro_number: "SARO-TEST".to_string(),
        amount: Uint128::new(300_000_000_000u128),
        release_date: Some("2024-01-15".to_string()),
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

    // Create Obligation with 100 billion
    let create_obligation_msg = ExecuteMsg::CreateObligation {
        id: "obl_small".to_string(),
        saro_id: "saro_test".to_string(),
        obligation_number: "OBL-SMALL".to_string(),
        amount: Uint128::new(100_000_000_000u128), // 100 billion
        description: Some("Small obligation".to_string()),
        payee: Some("Test Corp".to_string()),
        obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

    // Create NCA with 200 billion
    let create_nca_msg = ExecuteMsg::CreateNCA {
        id: "nca_large".to_string(),
        saro_ids: vec!["saro_test".to_string()],
        nca_number: "NCA-LARGE".to_string(),
        amount: Uint128::new(200_000_000_000u128), // 200 billion
        approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
        issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
        release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
        department: Some("DBM".to_string()),
        agency: Some("Treasury".to_string()),
        operating_unit: Some("Central Office".to_string()),
        purpose: Some("Large cash allocation".to_string()),
        cancel_remarks: None,
        release_type_cd: Some("REGULAR".to_string()),
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg).unwrap();

    // Try to create DV with 150 billion (exceeds Obligation balance of 100 billion)
    let create_dv_msg = ExecuteMsg::CreateDisbursementVoucher {
        id: "dv_oversized".to_string(),
        obligation_id: "obl_small".to_string(),
        nca_id: "nca_large".to_string(),
        dv_number: "DV-OVERSIZED".to_string(),
        amount: Uint128::new(150_000_000_000u128), // 150 billion - exceeds Obligation
        description: Some("Oversized disbursement".to_string()),
        payee: Some("Test Payee".to_string()),
        disbursement_voucher_date: Some(1709251200),  // 2024-03-01 Unix timestamp
    };
    
    let res = execute(deps.as_mut(), mock_env(), info.clone(), create_dv_msg);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Insufficient Obligation balance for DV"));
}

#[test]
fn test_disbursement_voucher_exceeds_nca_balance_renamed() {
    use cosmwasm_std::Uint128;
    
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg { count: 0 };
    let info = mock_info("creator123", &coins(1000, "token"));
    let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Create complete chain: GAA -> PAP -> SARO -> Obligation and NCA
    let create_gaa_msg = ExecuteMsg::CreateGAA {
        id: "gaa_2024".to_string(),
        year: 2024,
        total_amount: Uint128::new(1_000_000_000_000u128),
        status: "Active".to_string(),
        token_name: "GAA 2024 Peso".to_string(),
        token_symbol: "GAAPESO".to_string(),
        token_decimals: 6,
        cw20_code_id: 1,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

    let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

    let create_saro_msg = ExecuteMsg::CreateSARO {
        id: "saro_test".to_string(),
        pap_id: "pap_test".to_string(),
        saro_number: "SARO-TEST".to_string(),
        amount: Uint128::new(300_000_000_000u128),
        release_date: Some("2024-01-15".to_string()),
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

    // Create Obligation with 200 billion
    let create_obligation_msg = ExecuteMsg::CreateObligation {
        id: "obl_large".to_string(),
        saro_id: "saro_test".to_string(),
        obligation_number: "OBL-LARGE".to_string(),
        amount: Uint128::new(200_000_000_000u128), // 200 billion
        description: Some("Large obligation".to_string()),
        payee: Some("Test Corp".to_string()),
        obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

    // Create NCA with 100 billion
    let create_nca_msg = ExecuteMsg::CreateNCA {
        id: "nca_small".to_string(),
        saro_ids: vec!["saro_test".to_string()],
        nca_number: "NCA-SMALL".to_string(),
        amount: Uint128::new(100_000_000_000u128), // 100 billion
        approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
        issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
        release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
        department: Some("DBM".to_string()),
        agency: Some("Treasury".to_string()),
        operating_unit: Some("Central Office".to_string()),
        purpose: Some("Small cash allocation".to_string()),
        cancel_remarks: None,
        release_type_cd: Some("REGULAR".to_string()),
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg).unwrap();

    // Try to create DV with 250 billion (exceeds Obligation balance of 200 billion)
    let create_dv_msg = ExecuteMsg::CreateDisbursementVoucher {
        id: "dv_oversized".to_string(),
        obligation_id: "obl_large".to_string(),
        nca_id: "nca_small".to_string(),
        dv_number: "DV-OVERSIZED".to_string(),
        amount: Uint128::new(250_000_000_000u128), // 250 billion - exceeds Obligation
        description: Some("Oversized disbursement".to_string()),
        payee: Some("Test Payee".to_string()),
        disbursement_voucher_date: Some(1709251200),  // 2024-03-01 Unix timestamp
    };
    
    let res = execute(deps.as_mut(), mock_env(), info.clone(), create_dv_msg);
    assert!(res.is_err());
    assert!(res.unwrap_err().to_string().contains("Insufficient Obligation balance for DV"));
}

#[test]
fn test_multiple_disbursement_vouchers_balance_tracking() {
    use cosmwasm_std::Uint128;
    
    let mut deps = mock_dependencies();
    let msg = InstantiateMsg { count: 0 };
    let info = mock_info("creator123", &coins(1000, "token"));
    let _res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Create complete chain: GAA -> PAP -> SARO -> Obligation and NCA
    let create_gaa_msg = ExecuteMsg::CreateGAA {
        id: "gaa_2024".to_string(),
        year: 2024,
        total_amount: Uint128::new(1_000_000_000_000u128),
        status: "Active".to_string(),
        token_name: "GAA 2024 Peso".to_string(),
        token_symbol: "GAAPESO".to_string(),
        token_decimals: 6,
        cw20_code_id: 1,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_gaa_msg).unwrap();

    let create_pap_msg = create_pap!(
            "pap_test".to_string(),
            "gaa_2024".to_string(),
            "Test".to_string(),
            Uint128::new(500_000_000_000u128),
        );
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_pap_msg).unwrap();

    let create_saro_msg = ExecuteMsg::CreateSARO {
        id: "saro_test".to_string(),
        pap_id: "pap_test".to_string(),
        saro_number: "SARO-TEST".to_string(),
        amount: Uint128::new(300_000_000_000u128),
        release_date: Some("2024-01-15".to_string()),
        department: None,
        agency: None,
        operating_unit: None,
        purpose: None,
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_saro_msg).unwrap();

    // Create Obligation with 300 billion
    let create_obligation_msg = ExecuteMsg::CreateObligation {
        id: "obl_multi".to_string(),
        saro_id: "saro_test".to_string(),
        obligation_number: "OBL-MULTI".to_string(),
        amount: Uint128::new(300_000_000_000u128), // 300 billion
        description: Some("Multi-DV obligation".to_string()),
        payee: Some("Test Corp".to_string()),
        obligation_date: Some(1706745600),  // 2024-02-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_obligation_msg).unwrap();

    // Create NCA with 300 billion
    let create_nca_msg = ExecuteMsg::CreateNCA {
        id: "nca_multi".to_string(),
        saro_ids: vec!["saro_test".to_string()],
        nca_number: "NCA-MULTI".to_string(),
        amount: Uint128::new(300_000_000_000u128), // 300 billion
        approved_date: Some(1708387200),  // 2024-02-20 00:00:00 UTC
        issue_date: Some(1708819200),     // 2024-02-25 00:00:00 UTC
        release_date: Some(1709251200),   // 2024-03-01 00:00:00 UTC
        department: Some("DBM".to_string()),
        agency: Some("Treasury".to_string()),
        operating_unit: Some("Central Office".to_string()),
        purpose: Some("Multi-purpose cash allocation".to_string()),
        cancel_remarks: None,
        release_type_cd: Some("REGULAR".to_string()),
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_nca_msg).unwrap();

    // Create first DV with 100 billion
    let create_dv1_msg = ExecuteMsg::CreateDisbursementVoucher {
        id: "dv_001".to_string(),
        obligation_id: "obl_multi".to_string(),
        nca_id: "nca_multi".to_string(),
        dv_number: "DV-001".to_string(),
        amount: Uint128::new(100_000_000_000u128), // 100 billion
        description: Some("First disbursement".to_string()),
        payee: Some("Payee 1".to_string()),
        disbursement_voucher_date: Some(1709251200),  // 2024-03-01 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_dv1_msg).unwrap();

    // Verify balances after first DV (only Obligation deducted)
    let obligation_after_1 = query::get_obligation(deps.as_ref(), "saro_test".to_string(), "obl_multi".to_string()).unwrap();
    let nca_after_1 = query::get_nca(deps.as_ref(), "nca_multi".to_string()).unwrap();
    assert_eq!(obligation_after_1.available_amount_for_disbursement_vouchers, Uint128::new(200_000_000_000u128)); // 200 billion remaining (300-100)
    // Still no disbursements; NCA liquidated amount remains zero
    assert_eq!(nca_after_1.liquidated_amount_from_disbursements, Uint128::zero());

    // Create second DV with 150 billion
    let create_dv2_msg = ExecuteMsg::CreateDisbursementVoucher {
        id: "dv_002".to_string(),
        obligation_id: "obl_multi".to_string(),
        nca_id: "nca_multi".to_string(),
        dv_number: "DV-002".to_string(),
        amount: Uint128::new(150_000_000_000u128), // 150 billion
        description: Some("Second disbursement".to_string()),
        payee: Some("Payee 2".to_string()),
        disbursement_voucher_date: Some(1710460800),  // 2024-03-15 Unix timestamp
    };
    let _res = execute(deps.as_mut(), mock_env(), info.clone(), create_dv2_msg).unwrap();

    // Verify final balances after second DV (only Obligation deducted)
    let obligation_final = query::get_obligation(deps.as_ref(), "saro_test".to_string(), "obl_multi".to_string()).unwrap();
    let nca_final = query::get_nca(deps.as_ref(), "nca_multi".to_string()).unwrap();
    assert_eq!(obligation_final.available_amount_for_disbursement_vouchers, Uint128::new(50_000_000_000u128)); // 50 billion remaining (300-100-150)
    // Even after multiple DVs, NCA liquidated amount should still be zero until disbursements are created
    assert_eq!(nca_final.liquidated_amount_from_disbursements, Uint128::zero());

    // Verify both DVs can be queried
    let dvs_by_obligation = query::get_disbursement_vouchers_by_obligation(deps.as_ref(), "obl_multi".to_string(), None, None).unwrap();
    let dvs_by_nca = query::get_disbursement_vouchers_by_nca(deps.as_ref(), "nca_multi".to_string(), None, None).unwrap();
    
    assert_eq!(dvs_by_obligation.disbursement_vouchers.len(), 2);
    assert_eq!(dvs_by_nca.disbursement_vouchers.len(), 2);
    
    // Verify total DV amounts
    let total_dv_amount: u128 = dvs_by_obligation.disbursement_vouchers.iter().map(|dv| dv.amount.u128()).sum();
    assert_eq!(total_dv_amount, 250_000_000_000u128); // 100B + 150B = 250B
}

}
