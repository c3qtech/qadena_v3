#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdError, StdResult,
};
use cw2::set_contract_version;
use cw_storage_plus::Bound;

use crate::error::ContractError;
use crate::msg::{
    CountResponse, ExecuteMsg, InstantiateMsg, PaginatedEnpChangesResponse, PaginatedEnpsResponse,
    PaginatedEntriesResponse, QueryMsg,
};
use crate::state::{
    DocRefs, Enp, EnpChange, EnpRecord, FieldChange, NotarialBookEntry, Party, BY_ENF_SEQ,
    BY_ENP_SEQ, ENF_COUNT, ENPS, ENP_BY_COMMISSION, ENP_BY_EMAIL, ENP_CHANGES, ENP_COUNT,
    ENP_TOTAL, ENTRIES,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:enf_notarial_book";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    ENF_COUNT.save(deps.storage, &0u64)?;
    ENP_TOTAL.save(deps.storage, &0u64)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterEnp {
            roll_number,
            email,
            full_name,
            commission_number,
        } => execute::register_enp(deps, env, info, roll_number, email, full_name, commission_number),
        ExecuteMsg::UpdateEnp {
            roll_number,
            email,
            full_name,
            commission_number,
            changed_by,
        } => execute::update_enp(
            deps,
            env,
            roll_number,
            email,
            full_name,
            commission_number,
            changed_by,
        ),
        ExecuteMsg::CreateEntry {
            id,
            enp,
            entry_date,
            status,
            mode,
            notarization_type,
            document_title,
            document_type,
            parties,
            references,
            cancellation_reason,
            cancelled_by,
        } => execute::create_entry(
            deps,
            env,
            info,
            id,
            enp,
            entry_date,
            status,
            mode,
            notarization_type,
            document_title,
            document_type,
            parties,
            references,
            cancellation_reason,
            cancelled_by,
        ),
    }
}

pub mod execute {
    use super::*;

    // Reject an empty (or whitespace-only) required field.
    fn require(value: &str, field: &str) -> Result<(), ContractError> {
        if value.trim().is_empty() {
            return Err(ContractError::Required {
                field: field.to_string(),
            });
        }
        Ok(())
    }

    // Reject if `value` already maps to a different roll_number in `index`.
    fn ensure_unique(
        deps: &DepsMut,
        index: &cw_storage_plus::Map<String, String>,
        value: &str,
        roll_number: &str,
        entity: &str,
    ) -> Result<(), ContractError> {
        if value.is_empty() {
            return Ok(());
        }
        if let Some(existing) = index.may_load(deps.storage, value.to_string())? {
            if existing != roll_number {
                return Err(ContractError::AlreadyExists {
                    entity: entity.to_string(),
                });
            }
        }
        Ok(())
    }

    pub fn register_enp(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        roll_number: String,
        email: String,
        full_name: String,
        commission_number: String,
    ) -> Result<Response, ContractError> {
        require(&roll_number, "roll_number")?;
        require(&email, "email")?;
        require(&full_name, "full_name")?;
        require(&commission_number, "commission_number")?;

        if ENPS.has(deps.storage, roll_number.clone()) {
            return Err(ContractError::AlreadyExists {
                entity: "ENP".to_string(),
            });
        }
        ensure_unique(&deps, &ENP_BY_EMAIL, &email, &roll_number, "ENP email")?;
        ensure_unique(
            &deps,
            &ENP_BY_COMMISSION,
            &commission_number,
            &roll_number,
            "ENP commission number",
        )?;

        let now = env.block.time.seconds();
        let record = EnpRecord {
            roll_number: roll_number.clone(),
            email: email.clone(),
            full_name,
            commission_number: commission_number.clone(),
            change_count: 0,
            created_by: info.sender,
            created_at: now,
            updated_at: now,
        };
        ENPS.save(deps.storage, roll_number.clone(), &record)?;
        let enp_total = ENP_TOTAL.may_load(deps.storage)?.unwrap_or(0) + 1;
        ENP_TOTAL.save(deps.storage, &enp_total)?;
        if !email.is_empty() {
            ENP_BY_EMAIL.save(deps.storage, email, &roll_number)?;
        }
        if !commission_number.is_empty() {
            ENP_BY_COMMISSION.save(deps.storage, commission_number, &roll_number)?;
        }

        Ok(Response::new()
            .add_attribute("action", "register_enp")
            .add_attribute("roll_number", roll_number))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn update_enp(
        deps: DepsMut,
        env: Env,
        roll_number: String,
        email: String,
        full_name: String,
        commission_number: String,
        changed_by: String,
    ) -> Result<Response, ContractError> {
        require(&roll_number, "roll_number")?;
        require(&email, "email")?;
        require(&full_name, "full_name")?;
        require(&commission_number, "commission_number")?;
        require(&changed_by, "changed_by")?;

        let mut record = ENPS
            .may_load(deps.storage, roll_number.clone())?
            .ok_or_else(|| ContractError::NotFound {
                entity: "ENP".to_string(),
            })?;

        // Uniqueness for any changed indexed field.
        if email != record.email {
            ensure_unique(&deps, &ENP_BY_EMAIL, &email, &roll_number, "ENP email")?;
        }
        if commission_number != record.commission_number {
            ensure_unique(
                &deps,
                &ENP_BY_COMMISSION,
                &commission_number,
                &roll_number,
                "ENP commission number",
            )?;
        }

        let mut changes: Vec<FieldChange> = Vec::new();
        if email != record.email {
            // Move the email index.
            if !record.email.is_empty() {
                ENP_BY_EMAIL.remove(deps.storage, record.email.clone());
            }
            if !email.is_empty() {
                ENP_BY_EMAIL.save(deps.storage, email.clone(), &roll_number)?;
            }
            changes.push(FieldChange {
                field: "email".to_string(),
                old: record.email.clone(),
                new: email.clone(),
            });
            record.email = email;
        }
        if full_name != record.full_name {
            changes.push(FieldChange {
                field: "full_name".to_string(),
                old: record.full_name.clone(),
                new: full_name.clone(),
            });
            record.full_name = full_name;
        }
        if commission_number != record.commission_number {
            if !record.commission_number.is_empty() {
                ENP_BY_COMMISSION.remove(deps.storage, record.commission_number.clone());
            }
            if !commission_number.is_empty() {
                ENP_BY_COMMISSION.save(deps.storage, commission_number.clone(), &roll_number)?;
            }
            changes.push(FieldChange {
                field: "commission_number".to_string(),
                old: record.commission_number.clone(),
                new: commission_number.clone(),
            });
            record.commission_number = commission_number;
        }

        if changes.is_empty() {
            return Ok(Response::new()
                .add_attribute("action", "update_enp")
                .add_attribute("roll_number", roll_number)
                .add_attribute("changed", "0"));
        }

        let now = env.block.time.seconds();
        let seq = record.change_count;
        record.change_count += 1;
        record.updated_at = now;
        ENPS.save(deps.storage, roll_number.clone(), &record)?;
        ENP_CHANGES.save(
            deps.storage,
            (roll_number.clone(), seq),
            &EnpChange {
                roll_number: roll_number.clone(),
                seq,
                changes: changes.clone(),
                changed_by,
                changed_at: now,
            },
        )?;

        Ok(Response::new()
            .add_attribute("action", "update_enp")
            .add_attribute("roll_number", roll_number)
            .add_attribute("changed", changes.len().to_string()))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn create_entry(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
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
    ) -> Result<Response, ContractError> {
        // Required structural + identity fields. (parties / references / cancellation_* are
        // intentionally status-dependent — e.g. a CANCELLED/FAILED entry has no certificate — so
        // they are not required here.)
        require(&id, "id")?;
        require(&enp.roll_number, "enp.roll_number")?;
        require(&enp.email, "enp.email")?;
        require(&enp.full_name, "enp.full_name")?;
        require(&enp.commission_number, "enp.commission_number")?;
        require(&status, "status")?;
        require(&mode, "mode")?;
        require(&notarization_type, "notarization_type")?;
        require(&document_title, "document_title")?;
        require(&document_type, "document_type")?;
        if entry_date == 0 {
            return Err(ContractError::Required {
                field: "entry_date".to_string(),
            });
        }

        // Idempotency: never create the same entry twice (safe to retry the broadcast).
        if ENTRIES.has(deps.storage, id.clone()) {
            return Err(ContractError::AlreadyExists {
                entity: "NotarialBookEntry".to_string(),
            });
        }
        // The ENP must be registered (roll_number is the stable id).
        if !ENPS.has(deps.storage, enp.roll_number.clone()) {
            return Err(ContractError::NotFound {
                entity: "ENP".to_string(),
            });
        }

        let roll_number = enp.roll_number.clone();
        let enf_seq = ENF_COUNT.may_load(deps.storage)?.unwrap_or(0) + 1;
        let enp_seq = ENP_COUNT
            .may_load(deps.storage, roll_number.clone())?
            .unwrap_or(0)
            + 1;

        let entry = NotarialBookEntry {
            id: id.clone(),
            enf_seq,
            enp_seq,
            enp,
            entry_date,
            status: status.clone(),
            mode,
            notarization_type,
            document_title,
            document_type,
            parties,
            references,
            cancellation_reason,
            cancelled_by,
            created_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        ENTRIES.save(deps.storage, id.clone(), &entry)?;
        BY_ENF_SEQ.save(deps.storage, enf_seq, &id)?;
        BY_ENP_SEQ.save(deps.storage, (roll_number.clone(), enp_seq), &id)?;
        ENF_COUNT.save(deps.storage, &enf_seq)?;
        ENP_COUNT.save(deps.storage, roll_number.clone(), &enp_seq)?;

        // Emit the assigned sequence numbers so the Go backend can read them from tx events.
        Ok(Response::new()
            .add_attribute("action", "create_entry")
            .add_attribute("id", id)
            .add_attribute("enf_seq", enf_seq.to_string())
            .add_attribute("enp_seq", enp_seq.to_string())
            .add_attribute("roll_number", roll_number)
            .add_attribute("status", status))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetEnp { roll_number } => to_json_binary(&query::get_enp(deps, roll_number)?),
        QueryMsg::GetEnpByEmail { email } => to_json_binary(&query::get_enp_by_email(deps, email)?),
        QueryMsg::GetEnpByCommission { commission_number } => {
            to_json_binary(&query::get_enp_by_commission(deps, commission_number)?)
        }
        QueryMsg::GetEnps { start_after, limit } => {
            to_json_binary(&query::get_enps(deps, start_after, limit)?)
        }
        QueryMsg::GetEnpChanges {
            roll_number,
            start_after,
            limit,
        } => to_json_binary(&query::get_enp_changes(deps, roll_number, start_after, limit)?),
        QueryMsg::GetEntry { id } => to_json_binary(&query::get_entry(deps, id)?),
        QueryMsg::GetEntryByEnfSeq { enf_seq } => {
            to_json_binary(&query::get_entry_by_enf_seq(deps, enf_seq)?)
        }
        QueryMsg::GetEntries { start_after, limit } => {
            to_json_binary(&query::get_entries(deps, start_after, limit)?)
        }
        QueryMsg::GetEntriesByEnp {
            roll_number,
            start_after,
            limit,
        } => to_json_binary(&query::get_entries_by_enp(deps, roll_number, start_after, limit)?),
        QueryMsg::GetCount {} => to_json_binary(&query::get_count(deps)?),
    }
}

pub mod query {
    use super::*;

    pub fn get_enp(deps: Deps, roll_number: String) -> StdResult<EnpRecord> {
        ENPS.load(deps.storage, roll_number)
    }

    pub fn get_enp_by_email(deps: Deps, email: String) -> StdResult<EnpRecord> {
        let roll = ENP_BY_EMAIL
            .may_load(deps.storage, email.clone())?
            .ok_or_else(|| StdError::not_found(format!("ENP with email {}", email)))?;
        ENPS.load(deps.storage, roll)
    }

    pub fn get_enp_by_commission(deps: Deps, commission_number: String) -> StdResult<EnpRecord> {
        let roll = ENP_BY_COMMISSION
            .may_load(deps.storage, commission_number.clone())?
            .ok_or_else(|| {
                StdError::not_found(format!("ENP with commission {}", commission_number))
            })?;
        ENPS.load(deps.storage, roll)
    }

    pub fn get_enps(
        deps: Deps,
        start_after: Option<String>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEnpsResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(Bound::exclusive);
        let total = ENP_TOTAL.may_load(deps.storage)?.unwrap_or(0);

        let items: Vec<EnpRecord> = ENPS
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, r)| r))
            .collect::<StdResult<Vec<_>>>()?;

        let has_more = items.len() > limit;
        let enps: Vec<EnpRecord> = items.into_iter().take(limit).collect();
        let count = enps.len() as u32;
        Ok(PaginatedEnpsResponse {
            enps,
            total,
            count,
            has_more,
        })
    }

    pub fn get_enp_changes(
        deps: Deps,
        roll_number: String,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEnpChangesResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(Bound::exclusive);
        let total = ENPS
            .may_load(deps.storage, roll_number.clone())?
            .map(|r| r.change_count)
            .unwrap_or(0);

        let items: Vec<EnpChange> = ENP_CHANGES
            .prefix(roll_number)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, c)| c))
            .collect::<StdResult<Vec<_>>>()?;

        let has_more = items.len() > limit;
        let changes: Vec<EnpChange> = items.into_iter().take(limit).collect();
        let count = changes.len() as u32;
        Ok(PaginatedEnpChangesResponse {
            changes,
            total,
            count,
            has_more,
        })
    }

    pub fn get_entry(deps: Deps, id: String) -> StdResult<NotarialBookEntry> {
        ENTRIES.load(deps.storage, id)
    }

    pub fn get_entry_by_enf_seq(deps: Deps, enf_seq: u64) -> StdResult<NotarialBookEntry> {
        let id = BY_ENF_SEQ
            .may_load(deps.storage, enf_seq)?
            .ok_or_else(|| StdError::not_found(format!("entry with enf_seq {}", enf_seq)))?;
        ENTRIES.load(deps.storage, id)
    }

    pub fn get_count(deps: Deps) -> StdResult<CountResponse> {
        Ok(CountResponse {
            count: ENF_COUNT.may_load(deps.storage)?.unwrap_or(0),
        })
    }

    pub fn get_entries(
        deps: Deps,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEntriesResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(Bound::exclusive);
        let total = ENF_COUNT.may_load(deps.storage)?.unwrap_or(0);

        let ids: Vec<String> = BY_ENF_SEQ
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, id)| id))
            .collect::<StdResult<Vec<_>>>()?;

        load_entries(deps, ids, limit, total)
    }

    pub fn get_entries_by_enp(
        deps: Deps,
        roll_number: String,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEntriesResponse> {
        let limit = limit.unwrap_or(30).min(100) as usize;
        let start = start_after.map(Bound::exclusive);
        let total = ENP_COUNT
            .may_load(deps.storage, roll_number.clone())?
            .unwrap_or(0);

        let ids: Vec<String> = BY_ENP_SEQ
            .prefix(roll_number)
            .range(deps.storage, start, None, Order::Ascending)
            .take(limit + 1)
            .map(|item| item.map(|(_, id)| id))
            .collect::<StdResult<Vec<_>>>()?;

        load_entries(deps, ids, limit, total)
    }

    // Shared: trim the limit+1 lookahead, load the full entries, and build the paginated response.
    fn load_entries(
        deps: Deps,
        ids: Vec<String>,
        limit: usize,
        total: u64,
    ) -> StdResult<PaginatedEntriesResponse> {
        let has_more = ids.len() > limit;
        let ids: Vec<String> = ids.into_iter().take(limit).collect();
        let mut entries: Vec<NotarialBookEntry> = Vec::with_capacity(ids.len());
        for id in ids {
            entries.push(ENTRIES.load(deps.storage, id)?);
        }
        let count = entries.len() as u32;
        Ok(PaginatedEntriesResponse {
            entries,
            total,
            count,
            has_more,
        })
    }
}
