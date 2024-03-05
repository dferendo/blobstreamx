use std::env;
use std::str::FromStr;

use alloy_primitives::{Address, Bytes, FixedBytes, B256};
use alloy_sol_types::{sol, SolType};
use anyhow::Result;
use blobstreamx::input::DataCommitmentInputs;
use ethers::abi::AbiEncode;
use ethers::contract::abigen;
use ethers::providers::{Http, Provider};
use ethers::signers::LocalWallet;
use log::{error, info};
use succinct_client::request::SuccinctClient;
use tendermintx::input::InputDataFetcher;

// Note: Update ABI when updating contract.
abigen!(BlobstreamX, "./abi/BlobstreamX.abi.json");

struct BlobstreamXConfig {
    address: Address,
    chain_id: u32,
    local_prove_mode: bool,
    local_relay_mode: bool,
}

type NextHeaderInputTuple = sol! { tuple(uint64, bytes32) };

type HeaderRangeInputTuple = sol! { tuple(uint64, bytes32, uint64) };

struct BlobstreamXOperator {
    config: BlobstreamXConfig,
    ethereum_rpc_url: String,
    wallet: Option<LocalWallet>,
    contract: BlobstreamX<Provider<Http>>,
    client: SuccinctClient,
    data_fetcher: InputDataFetcher,
}

impl BlobstreamXOperator {
    pub async fn new() -> Self {
        let contract_address = env::var("CONTRACT_ADDRESS").expect("CONTRACT_ADDRESS must be set");
        let chain_id = env::var("CHAIN_ID").expect("CHAIN_ID must be set");
        let address = contract_address
            .parse::<Address>()
            .expect("invalid address");

        // Local prove mode and local relay mode are optional and default to false.
        let local_prove_mode: String =
            env::var("LOCAL_PROVE_MODE").unwrap_or(String::from("false"));
        let local_prove_mode_bool = local_prove_mode.parse::<bool>().unwrap();
        let local_relay_mode: String =
            env::var("LOCAL_RELAY_MODE").unwrap_or(String::from("false"));
        let local_relay_mode_bool = local_relay_mode.parse::<bool>().unwrap();

        let ethereum_rpc_url = env::var("RPC_URL").expect("RPC_URL must be set");
        let provider = Provider::<Http>::try_from(ethereum_rpc_url.clone())
            .expect("could not connect to client");

        let contract = BlobstreamX::new(address.0 .0, provider.into());

        let config = BlobstreamXConfig {
            address,
            chain_id: chain_id.parse::<u32>().expect("invalid chain id"),
            local_prove_mode: local_prove_mode_bool,
            local_relay_mode: local_relay_mode_bool,
        };

        let data_fetcher = InputDataFetcher::bridge_commitment_new();

        let succinct_rpc_url = env::var("SUCCINCT_RPC_URL").expect("SUCCINCT_RPC_URL must be set");
        let succinct_api_key = env::var("SUCCINCT_API_KEY").expect("SUCCINCT_API_KEY must be set");

        let private_key: Option<String>;
        let wallet: Option<LocalWallet>;

        if config.local_relay_mode {
            // If true, set the variables with the required values
            private_key = Some(env::var("PRIVATE_KEY").expect("PRIVATE_KEY must be set"));
            wallet = Some(
                LocalWallet::from_str(private_key.as_ref().unwrap()).expect("invalid private key"),
            );
        } else {
            wallet = None;
        }

        let client = SuccinctClient::new(
            succinct_rpc_url,
            succinct_api_key,
            config.local_prove_mode,
            config.local_relay_mode,
        );

        Self {
            config,
            ethereum_rpc_url,
            wallet,
            contract,
            client,
            data_fetcher,
        }
    }

    async fn request_next_header(
        &self,
        trusted_block: u64,
        next_header_function_id: B256,
    ) -> Result<String> {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = NextHeaderInputTuple::abi_encode_packed(&(trusted_block, trusted_header_hash));

        let commit_next_header_call = CommitNextHeaderCall { trusted_block };
        let function_data = commit_next_header_call.encode();

        let request_id = self
            .client
            .submit_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                next_header_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn request_header_range(
        &self,
        trusted_block: u64,
        target_block: u64,
        header_range_function_id: B256,
    ) -> Result<String> {
        let trusted_header_hash = self
            .contract
            .block_height_to_header_hash(trusted_block)
            .await
            .unwrap();

        let input = HeaderRangeInputTuple::abi_encode_packed(&(
            trusted_block,
            trusted_header_hash,
            target_block,
        ));

        let commit_header_range_call = CommitHeaderRangeCall { target_block };
        let function_data = commit_header_range_call.encode();

        let request_id = self
            .client
            .submit_request(
                self.config.chain_id,
                self.config.address,
                function_data.into(),
                header_range_function_id,
                Bytes::copy_from_slice(&input),
            )
            .await?;

        Ok(request_id)
    }

    async fn run(&mut self) {
        info!("Starting BlobstreamX operator");
        // Check every 20 minutes.
        // Note: This should be longer than the time to generate a proof to avoid concurrent proof
        // requests.
        const LOOP_DELAY: u64 = 20;

        let post_delay_minutes = env::var("POST_DELAY_MINUTES")
            .expect("POST_DELAY_MINUTES must be set")
            .parse::<u64>()
            .expect("invalid POST_DELAY_MINUTES");

        // Attempt to update the contract if it is more than post_delay_minutes behind the head of
        // the chain.
        let post_delay_blocks = post_delay_minutes * 5;

        let header_range_max = self.contract.data_commitment_max().await.unwrap();

        // Something is wrong with the contract if this is true.
        if header_range_max == 0 {
            panic!("header_range_max must be greater than 0");
        }

        loop {
            // Get the function IDs from the contract (they can change if the contract is updated).
            let next_header_function_id =
                FixedBytes(self.contract.next_header_function_id().await.unwrap());
            let header_range_function_id =
                FixedBytes(self.contract.header_range_function_id().await.unwrap());

            let current_block = self.contract.latest_block().await.unwrap();
            info!("The latest block stored the contract is: {}", current_block);

            // Get the head of the chain.
            let latest_signed_header = self.data_fetcher.get_latest_signed_header().await;
            let latest_block = latest_signed_header.header.height.value();

            // Subtract 5 blocks to account for the time it takes for a block to be processed by
            // consensus.
            let latest_stable_block = latest_block - 5;
            info!("The latest stable block is: {}", latest_stable_block);

            let delay = latest_stable_block - current_block;

            if delay >= post_delay_blocks {
                // The block with the greatest height that the contract can step to.
                let max_end_block =
                    std::cmp::min(latest_stable_block, current_block + header_range_max);

                let target_block = self
                    .data_fetcher
                    .find_block_to_request(current_block, max_end_block)
                    .await;

                if target_block - current_block == 1 {
                    // Request the next header if the target block is the next block.
                    match self
                        .request_next_header(current_block, next_header_function_id)
                        .await
                    {
                        Ok(request_id) => {
                            info!("Next header request submitted: {}", request_id);

                            // If in local mode, this will submit the request on-chain.
                            let res = self
                                .client
                                .relay_proof(
                                    request_id,
                                    Some(self.ethereum_rpc_url.as_ref()),
                                    self.wallet.clone(),
                                    None,
                                )
                                .await;
                            if res.is_err() {
                                error!("Relaying next header request failed: {:?}", res);
                            }
                        }
                        Err(e) => {
                            error!("Next header request failed: {}", e);
                            continue;
                        }
                    };
                } else {
                    // Request a header range if the target block is not the next block.
                    match self
                        .request_header_range(current_block, target_block, header_range_function_id)
                        .await
                    {
                        Ok(request_id) => {
                            info!("Header range request submitted: {}", request_id);

                            // If in local mode, this will submit the request on-chain.
                            let res = self
                                .client
                                .relay_proof(
                                    request_id,
                                    Some(self.ethereum_rpc_url.as_ref()),
                                    self.wallet.clone(),
                                    None,
                                )
                                .await;
                            if res.is_err() {
                                error!("Relaying header range request failed: {:?}", res);
                            }
                        }
                        Err(e) => {
                            error!("Header range request failed: {}", e);
                            continue;
                        }
                    };
                }
            } else {
                info!("The delay between the contract and the chain is {}, less than set delay of {} blocks. Sleeping.", delay, post_delay_blocks);
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(60 * LOOP_DELAY)).await;
        }
    }
}

#[tokio::main]
async fn main() {
    env::set_var("RUST_LOG", "info");
    dotenv::dotenv().ok();
    env_logger::init();

    let mut operator = BlobstreamXOperator::new().await;
    operator.run().await;
}
