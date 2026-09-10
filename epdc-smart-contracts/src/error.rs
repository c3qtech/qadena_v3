use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("{entity} not found")]
    NotFound { entity: String },

    #[error("{entity} already exists")]
    AlreadyExists { entity: String },

    #[error("{field} is required")]
    Required { field: String },

    #[error("invalid attestor class {class}")]
    InvalidClass { class: String },

    #[error("quorum not met: {valid} valid signatures, {disinterested} disinterested (need {need_total} incl. {need_disinterested} disinterested)")]
    QuorumNotMet {
        valid: u32,
        disinterested: u32,
        need_total: u32,
        need_disinterested: u32,
    },

    #[error("holder mismatch: expected {expected}, found {found}")]
    HolderMismatch { expected: String, found: String },
}
