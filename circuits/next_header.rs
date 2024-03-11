use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};
use tendermintx::config::TendermintConfig;
use tendermintx::step::{StepOffchainInputs, TendermintStepCircuit};

use crate::builder::DataCommitmentBuilder;
use crate::data_commitment::DataCommitmentOffchainInputs;

#[derive(Debug, Clone)]
pub struct CombinedStepCircuit<
    const MAX_VALIDATOR_SET_SIZE: usize,
    const CHAIN_ID_SIZE_BYTES: usize,
    C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
> {
    _phantom: std::marker::PhantomData<C>,
}

impl<
        const MAX_VALIDATOR_SET_SIZE: usize,
        const CHAIN_ID_SIZE_BYTES: usize,
        C: TendermintConfig<CHAIN_ID_SIZE_BYTES>,
    > Circuit for CombinedStepCircuit<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES, C>
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let prev_block_number = builder.evm_read::<U64Variable>();
        let prev_header_hash = builder.evm_read::<Bytes32Variable>();

        let one = builder.constant::<U64Variable>(1u64);
        let next_block_number = builder.add(prev_block_number, one);

        let next_header_hash = builder.step::<MAX_VALIDATOR_SET_SIZE, CHAIN_ID_SIZE_BYTES>(
            C::CHAIN_ID_BYTES,
            prev_block_number,
            prev_header_hash,
        );

        // Prove the data commitment (which only includes the prev_block_number's data hash).
        let data_commitment = builder.prove_next_header_data_commitment(
            prev_block_number,
            prev_header_hash,
            next_block_number,
        );

        builder.evm_write(next_header_hash);
        builder.evm_write(data_commitment);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<StepOffchainInputs<MAX_VALIDATOR_SET_SIZE>>();
        generator_registry.register_async_hint::<DataCommitmentOffchainInputs<1>>();
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};
    use subtle_encoding::hex;
    use tendermint::hash::{Algorithm, Hash};

    use super::*;
    use crate::consts::{Petrol1Config, PETROL_1_CHAIN_ID_SIZE_BYTES};

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const MAX_VALIDATOR_SET_SIZE: usize = 2;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, PETROL_1_CHAIN_ID_SIZE_BYTES, Petrol1Config>::define(&mut builder);
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, PETROL_1_CHAIN_ID_SIZE_BYTES, Petrol1Config>::register_generators(&mut hint_registry);
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, PETROL_1_CHAIN_ID_SIZE_BYTES, Petrol1Config>::register_gates(&mut gate_registry);

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    fn test_next_header_template<const MAX_VALIDATOR_SET_SIZE: usize>(
        prev_block: usize,
        prev_header_hash: [u8; 32],
    ) -> (H256, H256) {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        CombinedStepCircuit::<MAX_VALIDATOR_SET_SIZE, PETROL_1_CHAIN_ID_SIZE_BYTES, Petrol1Config>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        input.evm_write::<U64Variable>(prev_block as u64);
        input.evm_write::<Bytes32Variable>(H256::from_slice(prev_header_hash.as_slice()));

        log::debug!("Generating proof");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let (proof, mut output) = rt.block_on(async { circuit.prove_async(&input).await });

        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);

        let next_header_hash = output.evm_read::<Bytes32Variable>();
        println!("next_header_hash {:?}", next_header_hash);

        let data_commitment = output.evm_read::<Bytes32Variable>();
        println!("data_commitment {:?}", data_commitment);

        (next_header_hash, data_commitment)
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_small() {
        const MAX_VALIDATOR_SET_SIZE: usize = 4;

        let start_block = 2u64;
        let start_header_hash =
            hex::decode_upper("6CC3FB1D4379F9D21F8944CAB76901A1DC8D45F08A64A8ABE2D8436BA5E298C4")
                .unwrap();

        let (next_header_hash, data_commitment) = test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );

        assert_eq!(
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "9F2C593C74DA25ACDC34474C845463360E244EE15BFDC52D8308AB9339B95CC2",
            )
            .unwrap()
            .as_bytes(),
            next_header_hash.as_bytes()
        );

        assert_eq!(
            Hash::from_hex_upper(
                Algorithm::Sha256,
                "B5AA1D1FCC66E924808D5D94DC4134D876668A326A4989743F663F281F3DE3B6",
            )
            .unwrap()
            .as_bytes(),
            data_commitment.as_bytes()
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_medium() {
        const MAX_VALIDATOR_SET_SIZE: usize = 32;

        // This block is on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();

        test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_next_header_large() {
        const MAX_VALIDATOR_SET_SIZE: usize = 100;

        // This block is on Mocha-4 testnet.
        let start_block = 500u64;
        let start_header_hash =
            hex::decode_upper("46604E5FF15811D674CBAF2067DE6479A381EEC1BA046B90508939A685B40AE7")
                .unwrap();

        test_next_header_template::<MAX_VALIDATOR_SET_SIZE>(
            start_block as usize,
            start_header_hash.as_slice().try_into().unwrap(),
        );
    }
}
