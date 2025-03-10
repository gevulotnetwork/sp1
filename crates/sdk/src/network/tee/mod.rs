//! # TEE Integrity Proofs.
//!
//! An "integrity proof" is a signature over the outputs of the execution of a program computed
//! in a trusted execution environment (TEE).
//!
//! This acts a "2-factor authentication" for the SP1 proving system.

/// The API for the TEE server.
pub mod api;

/// The client for the TEE server.
pub mod client;

/// The type of TEE proof to use.
pub enum TEEProof {
    /// Use a Nitro TEE instance to create an integrity proof.
    NitroIntegrity,
    /// Do not create a TEE proof.
    None,
}
