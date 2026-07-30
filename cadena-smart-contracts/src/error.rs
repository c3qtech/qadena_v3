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
}
