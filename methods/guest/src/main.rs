// Copyright 2024 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(unused_doc_comments)]
#![no_main]

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolValue};
use risc0_steel::{config::ETH_SEPOLIA_CHAIN_SPEC, ethereum::EthEvmInput, Contract};
use risc0_zkvm::guest::env;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};

risc0_zkvm::guest::entry!(main);

/// Specify the function to call using the [`sol!`] macro.
/// This parses the Solidity syntax to generate a struct that implements the `SolCall` trait.
sol! {
    /// ERC-20 balance function signature.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Address of the deployed contract to call the function on (USDT contract on Sepolia).
const CONTRACT: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");

fn main() {
    // ------------------------------------------------------------------------
    // Verify locally signed message
    // ------------------------------------------------------------------------

    // Decode the verifying key, message, and signature from the inputs.
    let (encoded_verifying_key, signer, message, signature): (EncodedPoint,Address, Vec<u8>, Signature) = env::read();
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    // FIXME: there is a replay attack: once a signature is recvealed on the hard coded
    // message, anyone can run the proof with it, not just the account holder.
    // So need a way to statelessly check for reply or ensure the contract side logic
    // is statefull to prevent replay.
    verifying_key
        .verify(&message, &signature)
        .expect("ECDSA signature verification failed");

    // ------------------------------------------------------------------------
    // Run EVM view call
    // ------------------------------------------------------------------------

    /////////////////////////
    // Read the input from the guest environment.
    let input: EthEvmInput = env::read();

    // Converts the input into a `EvmEnv` for execution. The `with_chain_spec` method is used
    // to specify the chain configuration. It checks that the state matches the state root in the
    // header provided in the input.
    let env = input.into_env().with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    // TODO: We need to ensure the balance we check is controled by
    // the key that passed the sig check. It's liely more efficient to build
    // this call outside the guest and inside do a check the account matches?
    /// Function to call, implements the `SolCall` trait.
    let call = IERC20::balanceOfCall {
        account: signer,
    };

    // Execute the view call; it returns the result in the type generated by the `sol!` macro.
    let contract = Contract::new(CONTRACT, &env);
    let returns = contract.call_builder(&call).call();
    println!("GUEST: View call result (ballanceOf) = {}", returns._0);

    // ------------------------------------------------------------------------
    // Commit to journal (order and types are critical)
    // ------------------------------------------------------------------------

    env::commit(
        &(
            // Commit the block hash and number used when deriving `EvmEnv` to the journal.
            env.block_commitment().abi_encode(),   
            // Commit to the journal the verifying key and message that was signed.
            signer,
            message
        )
    );
}
