use crate::SP1Stdin;
use alloy_primitives::Address;
use serde::{Deserialize, Serialize};

use k256::ecdsa::Signature;

/// The request payload for the TEE server.
#[derive(Debug, Serialize, Deserialize)]
pub struct TEERequest {
    /// The network request id.
    pub id: [u8; 32],
    /// The program to execute.
    pub program: Vec<u8>,
    /// The stdin for the program.
    pub stdin: SP1Stdin,
}

/// The response payload from the TEE server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TEEResponse {
    /// The vkey computed by the TEE server.
    pub vkey: [u8; 32],
    /// The public values computed by the TEE server.
    pub public_values: Vec<u8>,
    /// The signature over the public values and the vkey.
    /// Computed as keccak256([`vkey` || `public_values`]).
    pub signature: Signature,
    /// The recovery id computed by the TEE server.
    pub recovery_id: u8,
}

impl TEEResponse {
    /// The bytes to prepend to the encoded proof bytes.
    #[must_use]
    pub fn as_prefix_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        // Push the selector
        bytes.extend_from_slice(&Self::selector());
        // Push v.
        bytes.extend_from_slice(&self.recovery_id.to_be_bytes());
        // Push r and s.
        bytes.extend_from_slice(&self.signature.to_bytes());

        bytes
    }

    /// The selector for the TEE verifier.
    fn selector() -> [u8; 4] {
        alloy_primitives::keccak256("SP1TeeVerifier")[0..4].try_into().unwrap()
    }
}

/// The response payload from the TEE server for the `get_address` endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAddressResponse {
    /// The address of the TEE signer.
    pub address: Address,
}

/// The underlying payload for the SSE event sent from the TEE server.
///
/// This is an implementation detail, and should not be used directly.
#[derive(Debug, Serialize, Deserialize)]
pub enum EventPayload {
    /// The request was successful.
    Success(TEEResponse),
    /// The execution failed.
    Error(String),
}
