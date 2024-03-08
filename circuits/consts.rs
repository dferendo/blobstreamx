pub use tendermint::merkle::HASH_SIZE;

/// The number of bits in a protobuf-encoded SHA256 hash.
pub const PROTOBUF_HASH_SIZE_BYTES: usize = HASH_SIZE + 2;

/// The number of bits in a protobuf-encoded tendermint block ID.
pub const PROTOBUF_BLOCK_ID_SIZE_BYTES: usize = 72;

// Depth of the proofs against the header.
pub const HEADER_PROOF_DEPTH: usize = 4;

// The maximum number of bytes in a protobuf-encoded varint.
// https://docs.tendermint.com/v0.34/tendermint-core/using-tendermint.html#tendermint-networks
pub const VARINT_BYTES_LENGTH_MAX: usize = 9;
pub const PROTOBUF_VARINT_SIZE_BYTES: usize = VARINT_BYTES_LENGTH_MAX + 1;

// The number of bytes in an encoded data root tuple.
pub const ENC_DATA_ROOT_TUPLE_SIZE_BYTES: usize = 64;

// Header indices for the Merkle tree.
pub const BLOCK_HEIGHT_INDEX: usize = 2;
pub const LAST_BLOCK_ID_INDEX: usize = 4;
pub const DATA_HASH_INDEX: usize = 6;

/// Petrol-1's chain config.
pub const PETROL_1_CHAIN_ID_BYTES: &[u8] = b"petrol-1";
pub const PETROL_1_CHAIN_ID_SIZE_BYTES: usize = PETROL_1_CHAIN_ID_BYTES.len();
#[derive(Debug, Clone, PartialEq)]
pub struct Petrol1Config;
impl TendermintConfig<PETROL_1_CHAIN_ID_SIZE_BYTES> for Petrol1Config {
    const CHAIN_ID_BYTES: &'static [u8] = PETROL_1_CHAIN_ID_BYTES;
    const SKIP_MAX: usize = SKIP_MAX;
}