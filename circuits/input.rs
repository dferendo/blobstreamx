use std::path::Path;
#[allow(unused_imports)]
use std::{env, fs};

use async_trait::async_trait;
use ethers::types::H256;
use log::info;
use plonky2x::frontend::merkle::tree::InclusionProof;
use plonky2x::prelude::RichField;
use serde::Deserialize;
use subtle_encoding::hex;
use tendermint::block::signed_header::SignedHeader;
use tendermint_proto::types::BlockId as RawBlockId;
use tendermint_proto::Protobuf;
use tendermintx::input::{InputDataFetcher, InputDataMode};

use crate::consts::*;

#[derive(Debug, Deserialize)]
pub struct DataCommitmentResponse {
    pub result: DataCommitment,
}

#[derive(Debug, Deserialize)]
pub struct DataCommitment {
    pub bridge_commitment: String,
}

#[async_trait]
pub trait DataCommitmentInputs {
    /// Get signed headers in the range [start_block_number, end_block_number] inclusive.
    async fn get_signed_header_range(
        &self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Vec<SignedHeader>;

    /// Gets the bridge commitment hash specified by the start block and end block, where
    /// end block is non-inclusive.
    async fn get_data_commitment(&mut self, start_block: u64, end_block: u64) -> [u8; 32];

    /// Gets an inclusion proof per block in the bridge commitment specified by the start and
    /// end block, where end block is non-inclusive.
    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> (
        [u8; 32],                                                             // start_header_hash
        [u8; 32],                                                             // end_header_hash
        Vec<[u8; 32]>,                                                        // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // last_block_id_proofs
        [u8; 32], // expected_data_commitment
    );
}

const MAX_NUM_RETRIES: usize = 3;

#[async_trait]
impl DataCommitmentInputs for InputDataFetcher {
    async fn get_signed_header_range(
        &self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> Vec<SignedHeader> {
        // Note: Tested with 500+ concurrent requests, but monitor for any issues.
        const MAX_BATCH_SIZE: usize = 200;

        let mut signed_headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let batch_end_block =
                std::cmp::min(curr_block + MAX_BATCH_SIZE as u64, end_block_number + 1);
            // Batch request the headers in the range [curr_block, batch_end_block).
            let batch_signed_header_futures = (curr_block..batch_end_block)
                .map(|i| self.get_signed_header_from_number(i))
                .collect::<Vec<_>>();
            let batch_signed_headers: Vec<SignedHeader> =
                futures::future::join_all(batch_signed_header_futures).await;
            signed_headers.extend(batch_signed_headers);

            curr_block += MAX_BATCH_SIZE as u64;
        }

        signed_headers
    }

    async fn get_data_commitment(&mut self, start_block: u64, end_block: u64) -> [u8; 32] {
        // If start_block == end_block, then return a dummy commitment.
        // This will occur in the context of data commitment's map reduce when leaves that contain blocks beyond the end_block.
        if end_block <= start_block {
            return [0u8; 32];
        }

        let file_name = format!(
            "{}/{}-{}/bridge_commitment.json",
            self.fixture_path,
            start_block.to_string().as_str(),
            end_block.to_string().as_str()
        );
        let route = format!(
            "bridge_commitment?start={}&end={}",
            start_block.to_string().as_str(),
            end_block.to_string().as_str()
        );
        let fetched_result = match &self.mode {
            InputDataMode::Rpc => {
                let res = self.request_from_rpc(&route, MAX_NUM_RETRIES).await;
                if self.save {
                    // Ensure the directory exists
                    if let Some(parent) = Path::new(&file_name).parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(file_name.as_str(), res.as_bytes()).expect("Unable to write file");
                }
                res
            }
            InputDataMode::Fixture => {
                let file_content = fs::read_to_string(file_name.as_str());
                info!("Fixture name: {}", file_name.as_str());
                file_content.unwrap()
            }
        };
        let v: DataCommitmentResponse =
            serde_json::from_str(&fetched_result).expect("Failed to parse JSON");

        hex::decode_upper(v.result.bridge_commitment)
            .unwrap()
            .try_into()
            .unwrap()
    }

    async fn get_data_commitment_inputs<const MAX_LEAVES: usize, F: RichField>(
        &mut self,
        start_block_number: u64,
        end_block_number: u64,
    ) -> (
        [u8; 32],                                                             // start_header_hash
        [u8; 32],                                                             // end_header_hash
        Vec<[u8; 32]>,                                                        // data_hashes
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F>>, // data_hash_proofs
        Vec<InclusionProof<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F>>, // last_block_id_proofs
        [u8; 32], // expected_data_commitment
    ) {
        let mut data_hashes = Vec::new();
        let mut data_hash_proofs = Vec::new();
        let mut last_block_id_proofs = Vec::new();
        let signed_headers = self
            .get_signed_header_range(start_block_number, end_block_number)
            .await;

        if end_block_number >= start_block_number {
            assert_eq!(
                signed_headers.len(),
                (end_block_number - start_block_number + 1) as usize
            );
        }
        for i in start_block_number..end_block_number + 1 {
            let signed_header = &signed_headers[(i - start_block_number) as usize];

            // Don't include the last results hash and corresponding proof of end_block, as the circuit's
            // bridge_commitment is computed over the range [start_block, end_block - 1].
            if i < end_block_number {
                let data_hash = signed_header.header.last_results_hash.unwrap();
                data_hashes.push(data_hash.as_bytes().try_into().unwrap());

                let data_hash_proof = self.get_inclusion_proof::<PROTOBUF_HASH_SIZE_BYTES, F>(
                    &signed_header.header,
                    LAST_RESULTS_HASH_INDEX as u64,
                    signed_header.header.last_results_hash.unwrap().encode_vec(),
                );
                data_hash_proofs.push(data_hash_proof);
            }

            // Don't include last_block_id of start, as the data_commitment circuit only requires
            // the last block id's of blocks in the range [start_block + 1, end_block]. Specifically,
            // the circuit needs the last_block_id proofs of data_commitment range shifted by one
            // block to the right.
            if i > start_block_number {
                let last_block_id_proof = self
                    .get_inclusion_proof::<PROTOBUF_BLOCK_ID_SIZE_BYTES, F>(
                        &signed_header.header,
                        LAST_BLOCK_ID_INDEX as u64,
                        Protobuf::<RawBlockId>::encode_vec(
                            signed_header.header.last_block_id.unwrap_or_default(),
                        ),
                    );
                last_block_id_proofs.push(last_block_id_proof);
            }
        }

        let mut data_hash_proofs_formatted = data_hash_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_HASH_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect::<Vec<_>>();

        let mut last_block_id_proofs_formatted = last_block_id_proofs
            .into_iter()
            .map(
                |proof| InclusionProof::<HEADER_PROOF_DEPTH, PROTOBUF_BLOCK_ID_SIZE_BYTES, F> {
                    proof: proof.proof,
                    leaf: proof.leaf,
                },
            )
            .collect::<Vec<_>>();

        let num_so_far = data_hashes.len();
        // Extend data_hashes, data_hash_proofs, and last_block_id_proofs to MAX_LEAVES.
        for _ in num_so_far..MAX_LEAVES {
            data_hashes.push([0u8; 32]);
            data_hash_proofs_formatted.push(InclusionProof::<
                HEADER_PROOF_DEPTH,
                PROTOBUF_HASH_SIZE_BYTES,
                F,
            > {
                proof: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                leaf: [0u8; PROTOBUF_HASH_SIZE_BYTES],
            });
            last_block_id_proofs_formatted.push(InclusionProof::<
                HEADER_PROOF_DEPTH,
                PROTOBUF_BLOCK_ID_SIZE_BYTES,
                F,
            > {
                proof: [H256::zero(); HEADER_PROOF_DEPTH].to_vec(),
                leaf: [0u8; PROTOBUF_BLOCK_ID_SIZE_BYTES],
            });
        }

        let expected_data_commitment = self
            .get_data_commitment(start_block_number, end_block_number)
            .await;

        let mut start_header = [0u8; 32];
        let mut end_header = [0u8; 32];
        // If start_block_number >= end_block_number, then start_header and end_header are dummy values.
        if start_block_number < end_block_number {
            start_header = signed_headers[0]
                .header
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
            end_header = signed_headers[signed_headers.len() - 1]
                .header
                .hash()
                .as_bytes()
                .try_into()
                .unwrap();
        }

        (
            start_header,
            end_header,
            data_hashes,
            data_hash_proofs_formatted,
            last_block_id_proofs_formatted,
            expected_data_commitment,
        )
    }
}

#[cfg(test)]
mod tests {
    use tendermint::hash::{Algorithm, Hash};
    use tendermintx::input::InputDataFetcher;

    use crate::input::DataCommitmentInputs;

    #[tokio::test]
    async fn test_get_signed_header_range() {
        let start_block = 2u64;
        let end_block = 6u64; // Inclusive

        let data_fetcher = InputDataFetcher::default();

        let signed_headers = data_fetcher
            .get_signed_header_range(start_block, end_block)
            .await;

        // Height 2
        assert_eq!(
            signed_headers[0].commit.block_id.hash,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "6CC3FB1D4379F9D21F8944CAB76901A1DC8D45F08A64A8ABE2D8436BA5E298C4",
            )
            .unwrap()
        );

        // Height 3
        assert_eq!(
            signed_headers[1].commit.block_id.hash,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "9F2C593C74DA25ACDC34474C845463360E244EE15BFDC52D8308AB9339B95CC2",
            )
            .unwrap()
        );

        // Height 4
        assert_eq!(
            signed_headers[2].commit.block_id.hash,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "3836C723CCFC773A0CB7D6AA9382B9F8BE0128B60504CBB8770D22EB4251B9A9",
            )
            .unwrap()
        );

        // Height 5
        assert_eq!(
            signed_headers[3].commit.block_id.hash,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "4D02C05EB799C82F28E14E28741A7142E1D0370369B6DE83B0DFA1886C1F7717",
            )
            .unwrap()
        );

        // Height 6
        assert_eq!(
            signed_headers[4].commit.block_id.hash,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "11F76B0D87679841CAC3BE7918BE6E8D0308CB9B7AD5C79A04EB53159779E25A",
            )
            .unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_data_commitment() {
        let start_block = 2u64;
        let end_block = 6u64; // Not inclusive

        let mut data_fetcher = InputDataFetcher::default();

        let data_commitment = data_fetcher
            .get_data_commitment(start_block, end_block)
            .await;

        assert_eq!(
            data_commitment,
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "BCC70C867ACDEF1BF569308071806404B5202BAE0EB52E951A32B619978675DF",
            )
            .unwrap()
            .as_bytes()
        );
    }
}
