#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Order, Response, StdError, StdResult,
};
use cw2::set_contract_version;
use cw_storage_plus::Bound;

use crate::error::ContractError;
use crate::msg::{
    Attestation, AttestorsResponse, CountResponse, ExecuteMsg, HolderResponse, InstantiateMsg,
    PaginatedEventsResponse, QueryMsg, QuorumRulesResponse,
};
use crate::state::{
    AttestorClass, AttestorRecord, Config, RecordedAttestation, RegisterEvent, ATTESTORS,
    BY_INSTRUMENT, BY_SEQ, CONFIG, DISINTERESTED_MIN, EVENTS, EVENT_COUNT, HOLDER,
    INSTRUMENT_COUNT, QUORUM_EVENT_TYPES, QUORUM_MIN,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:epdc_register";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    CONFIG.save(
        deps.storage,
        &Config {
            operator: info.sender.clone(),
        },
    )?;
    EVENT_COUNT.save(deps.storage, &0u64)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("operator", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::RegisterAttestor {
            addr,
            class,
            name,
            pubkey_hex,
        } => execute::register_attestor(deps, env, info, addr, class, name, pubkey_hex),
        ExecuteMsg::DeactivateAttestor { addr } => {
            execute::deactivate_attestor(deps, info, addr)
        }
        ExecuteMsg::AppendEvent {
            id,
            instrument_ref,
            event_type,
            digest,
            reason_code,
            dsvs_doc_id,
            attestations,
        } => execute::append_event(
            deps,
            env,
            info,
            id,
            instrument_ref,
            event_type,
            digest,
            reason_code,
            dsvs_doc_id,
            attestations,
        ),
        ExecuteMsg::SetHolder {
            instrument_ref,
            holder,
            prev_holder,
        } => execute::set_holder(deps, instrument_ref, holder, prev_holder),
    }
}

pub mod execute {
    use super::*;

    fn require(value: &str, field: &str) -> Result<(), ContractError> {
        if value.trim().is_empty() {
            return Err(ContractError::Required {
                field: field.to_string(),
            });
        }
        Ok(())
    }

    fn only_operator(deps: &DepsMut, info: &MessageInfo) -> Result<(), ContractError> {
        let cfg = CONFIG.load(deps.storage)?;
        if cfg.operator != info.sender {
            return Err(ContractError::Unauthorized {});
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn register_attestor(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        addr: String,
        class: String,
        name: String,
        pubkey_hex: String,
    ) -> Result<Response, ContractError> {
        only_operator(&deps, &info)?;
        require(&addr, "addr")?;
        require(&name, "name")?;
        require(&pubkey_hex, "pubkey_hex")?;
        let class = AttestorClass::parse(&class)
            .ok_or(ContractError::InvalidClass { class })?;
        // A malformed pubkey should fail loudly at registration, not at the
        // first signature check.
        let pk = hex::decode(&pubkey_hex)
            .map_err(|_| StdError::generic_err("pubkey_hex is not hex"))?;
        if pk.len() != 33 {
            return Err(StdError::generic_err("pubkey must be 33-byte compressed secp256k1").into());
        }

        let attestor = deps.api.addr_validate(&addr)?;
        let record = AttestorRecord {
            addr: attestor.clone(),
            class,
            name,
            pubkey_hex,
            active: true,
            registered_at: env.block.time.seconds(),
        };
        ATTESTORS.save(deps.storage, attestor.clone(), &record)?;

        Ok(Response::new()
            .add_attribute("method", "register_attestor")
            .add_attribute("attestor", attestor)
            .add_attribute("class", record.class.as_str()))
    }

    pub fn deactivate_attestor(
        deps: DepsMut,
        info: MessageInfo,
        addr: String,
    ) -> Result<Response, ContractError> {
        only_operator(&deps, &info)?;
        let attestor = deps.api.addr_validate(&addr)?;
        let mut record = ATTESTORS
            .may_load(deps.storage, attestor.clone())?
            .ok_or(ContractError::NotFound {
                entity: format!("attestor {}", attestor),
            })?;
        record.active = false;
        ATTESTORS.save(deps.storage, attestor.clone(), &record)?;
        Ok(Response::new()
            .add_attribute("method", "deactivate_attestor")
            .add_attribute("attestor", attestor))
    }

    /// Verify every submitted attestation against the roster, count classes,
    /// and enforce quorum where the event type demands it. An invalid or
    /// unknown signature is a hard error — never silently dropped, because a
    /// certificate later cites what this event recorded.
    fn verify_attestations(
        deps: &DepsMut,
        digest_hex: &str,
        attestations: &[Attestation],
    ) -> Result<Vec<RecordedAttestation>, ContractError> {
        let digest = hex::decode(digest_hex)
            .map_err(|_| StdError::generic_err("digest is not hex"))?;
        if digest.len() != 32 {
            return Err(StdError::generic_err("digest must be 32 bytes (sha256)").into());
        }

        let mut recorded: Vec<RecordedAttestation> = Vec::with_capacity(attestations.len());
        for att in attestations {
            let addr = deps.api.addr_validate(&att.attestor)?;
            let record = ATTESTORS
                .may_load(deps.storage, addr.clone())?
                .ok_or(ContractError::NotFound {
                    entity: format!("attestor {}", addr),
                })?;
            if !record.active {
                return Err(ContractError::Unauthorized {});
            }
            // Duplicate attestor in one submission would double-count a class.
            if recorded.iter().any(|r| r.attestor == addr) {
                return Err(ContractError::AlreadyExists {
                    entity: format!("attestation from {}", addr),
                });
            }
            let sig = hex::decode(&att.signature_hex)
                .map_err(|_| StdError::generic_err("signature_hex is not hex"))?;
            let pk = hex::decode(&record.pubkey_hex)
                .map_err(|_| StdError::generic_err("stored pubkey is not hex"))?;
            let ok = deps
                .api
                .secp256k1_verify(&digest, &sig, &pk)
                .map_err(|e| StdError::generic_err(format!("signature verify: {}", e)))?;
            if !ok {
                return Err(StdError::generic_err(format!(
                    "invalid signature from {}",
                    addr
                ))
                .into());
            }
            recorded.push(RecordedAttestation {
                attestor: addr,
                class_at_signing: record.class.clone(),
                signature_hex: att.signature_hex.clone(),
            });
        }
        Ok(recorded)
    }

    /// The quorum arithmetic. The operator exclusion lives in
    /// AttestorClass::counts_as_disinterested — a compiled match arm this
    /// function merely consults. Nothing in storage or in any message can
    /// alter what a class counts toward.
    fn enforce_quorum(recorded: &[RecordedAttestation]) -> Result<(), ContractError> {
        let valid = recorded.len() as u32;
        let disinterested = recorded
            .iter()
            .filter(|r| r.class_at_signing.counts_as_disinterested())
            .count() as u32;
        if valid < QUORUM_MIN || disinterested < DISINTERESTED_MIN {
            return Err(ContractError::QuorumNotMet {
                valid,
                disinterested,
                need_total: QUORUM_MIN,
                need_disinterested: DISINTERESTED_MIN,
            });
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn append_event(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        id: String,
        instrument_ref: String,
        event_type: String,
        digest: String,
        reason_code: Option<String>,
        dsvs_doc_id: Option<String>,
        attestations: Vec<Attestation>,
    ) -> Result<Response, ContractError> {
        require(&id, "id")?;
        require(&instrument_ref, "instrument_ref")?;
        require(&event_type, "event_type")?;
        require(&digest, "digest")?;

        // Idempotency: the saga re-drives after a crash; a duplicate id means
        // this event is already on the register and the caller treats the
        // AlreadyExists error as success.
        if EVENTS.may_load(deps.storage, id.clone())?.is_some() {
            return Err(ContractError::AlreadyExists {
                entity: format!("event {}", id),
            });
        }

        let recorded = verify_attestations(&deps, &digest, &attestations)?;
        if QUORUM_EVENT_TYPES.contains(&event_type.as_str()) {
            enforce_quorum(&recorded)?;
        }

        let seq = EVENT_COUNT.load(deps.storage)? + 1;
        let instrument_seq = INSTRUMENT_COUNT
            .may_load(deps.storage, instrument_ref.clone())?
            .unwrap_or(0)
            + 1;

        let event = RegisterEvent {
            id: id.clone(),
            seq,
            instrument_seq,
            instrument_ref: instrument_ref.clone(),
            event_type: event_type.clone(),
            digest,
            reason_code,
            dsvs_doc_id,
            attestations: recorded,
            submitted_by: info.sender,
            created_at: env.block.time.seconds(),
        };

        EVENTS.save(deps.storage, id.clone(), &event)?;
        BY_SEQ.save(deps.storage, seq, &id)?;
        BY_INSTRUMENT.save(deps.storage, (instrument_ref.clone(), instrument_seq), &id)?;
        EVENT_COUNT.save(deps.storage, &seq)?;
        INSTRUMENT_COUNT.save(deps.storage, instrument_ref, &instrument_seq)?;

        Ok(Response::new()
            .add_attribute("method", "append_event")
            .add_attribute("id", id)
            .add_attribute("seq", seq.to_string())
            .add_attribute("event_type", event_type))
    }

    pub fn set_holder(
        deps: DepsMut,
        instrument_ref: String,
        holder: String,
        prev_holder: Option<String>,
    ) -> Result<Response, ContractError> {
        require(&instrument_ref, "instrument_ref")?;
        require(&holder, "holder")?;

        let current = HOLDER.may_load(deps.storage, instrument_ref.clone())?;
        // Compare-and-set: exactly one holder at any time (BRD FR-902); a
        // stale prev_holder means someone else assigned first and this
        // assignment must fail, never overwrite.
        if current != prev_holder {
            return Err(ContractError::HolderMismatch {
                expected: prev_holder.unwrap_or_else(|| "<unset>".to_string()),
                found: current.unwrap_or_else(|| "<unset>".to_string()),
            });
        }
        HOLDER.save(deps.storage, instrument_ref.clone(), &holder)?;

        Ok(Response::new()
            .add_attribute("method", "set_holder")
            .add_attribute("instrument_ref", instrument_ref)
            .add_attribute("holder", holder))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetEvent { id } => to_json_binary(&query::get_event(deps, id)?),
        QueryMsg::GetEventBySeq { seq } => to_json_binary(&query::get_event_by_seq(deps, seq)?),
        QueryMsg::GetEvents { start_after, limit } => {
            to_json_binary(&query::get_events(deps, start_after, limit)?)
        }
        QueryMsg::GetEventsByInstrument {
            instrument_ref,
            start_after,
            limit,
        } => to_json_binary(&query::get_events_by_instrument(
            deps,
            instrument_ref,
            start_after,
            limit,
        )?),
        QueryMsg::GetAttestors {} => to_json_binary(&query::get_attestors(deps)?),
        QueryMsg::GetHolder { instrument_ref } => {
            to_json_binary(&query::get_holder(deps, instrument_ref)?)
        }
        QueryMsg::GetCount {} => to_json_binary(&query::get_count(deps)?),
        QueryMsg::GetQuorumRules {} => to_json_binary(&query::get_quorum_rules()?),
    }
}

pub mod query {
    use super::*;

    const DEFAULT_LIMIT: u32 = 50;
    const MAX_LIMIT: u32 = 200;

    pub fn get_event(deps: Deps, id: String) -> StdResult<RegisterEvent> {
        EVENTS
            .may_load(deps.storage, id.clone())?
            .ok_or_else(|| StdError::not_found(format!("event {}", id)))
    }

    pub fn get_event_by_seq(deps: Deps, seq: u64) -> StdResult<RegisterEvent> {
        let id = BY_SEQ
            .may_load(deps.storage, seq)?
            .ok_or_else(|| StdError::not_found(format!("seq {}", seq)))?;
        get_event(deps, id)
    }

    pub fn get_events(
        deps: Deps,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEventsResponse> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let total = EVENT_COUNT.load(deps.storage)?;
        let start = start_after.map(Bound::exclusive);

        let mut events = Vec::new();
        for item in BY_SEQ.range(deps.storage, start, None, Order::Ascending) {
            let (_, id) = item?;
            events.push(get_event(deps, id)?);
            if events.len() > limit {
                break;
            }
        }
        let has_more = events.len() > limit;
        events.truncate(limit);

        Ok(PaginatedEventsResponse {
            count: events.len() as u32,
            events,
            total,
            has_more,
        })
    }

    pub fn get_events_by_instrument(
        deps: Deps,
        instrument_ref: String,
        start_after: Option<u64>,
        limit: Option<u32>,
    ) -> StdResult<PaginatedEventsResponse> {
        let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
        let total = INSTRUMENT_COUNT
            .may_load(deps.storage, instrument_ref.clone())?
            .unwrap_or(0);
        let start = start_after.map(Bound::exclusive);

        let mut events = Vec::new();
        for item in BY_INSTRUMENT.prefix(instrument_ref).range(
            deps.storage,
            start,
            None,
            Order::Ascending,
        ) {
            let (_, id) = item?;
            events.push(get_event(deps, id)?);
            if events.len() > limit {
                break;
            }
        }
        let has_more = events.len() > limit;
        events.truncate(limit);

        Ok(PaginatedEventsResponse {
            count: events.len() as u32,
            events,
            total,
            has_more,
        })
    }

    pub fn get_attestors(deps: Deps) -> StdResult<AttestorsResponse> {
        let mut attestors = Vec::new();
        for item in ATTESTORS.range(deps.storage, None, None, Order::Ascending) {
            let (_, record) = item?;
            attestors.push(record);
        }
        Ok(AttestorsResponse { attestors })
    }

    pub fn get_holder(deps: Deps, instrument_ref: String) -> StdResult<HolderResponse> {
        let holder = HOLDER.may_load(deps.storage, instrument_ref.clone())?;
        Ok(HolderResponse {
            instrument_ref,
            holder,
        })
    }

    pub fn get_count(deps: Deps) -> StdResult<CountResponse> {
        Ok(CountResponse {
            count: EVENT_COUNT.load(deps.storage)?,
        })
    }

    pub fn get_quorum_rules() -> StdResult<QuorumRulesResponse> {
        Ok(QuorumRulesResponse {
            quorum_min: QUORUM_MIN,
            disinterested_min: DISINTERESTED_MIN,
            quorum_event_types: QUORUM_EVENT_TYPES.iter().map(|s| s.to_string()).collect(),
            // Compiled: AttestorClass::Operator.counts_as_disinterested().
            operator_counts_as_disinterested: AttestorClass::Operator.counts_as_disinterested(),
        })
    }
}
