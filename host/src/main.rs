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

use alloy_primitives::{address, Address};
use alloy_sol_types::{sol, SolCall, SolValue};
use anyhow::{Context, Result};
use clap::Parser;
use erc20_methods::ERC20_GUEST_ELF;
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    EncodedPoint,
};
use risc0_steel::{config::ETH_SEPOLIA_CHAIN_SPEC, ethereum::EthEvmEnv, Contract, EvmBlockHeader};
use risc0_zkvm::{default_executor, ExecutorEnv};
use tracing_subscriber::EnvFilter;

sol! {
    /// ERC-20 balance function signature.
    /// This must match the signature in the guest.
    interface IERC20 {
        function balanceOf(address account) external view returns (uint);
    }
}

/// Function to call, implements the [SolCall] trait.
const CALL: IERC20::balanceOfCall = IERC20::balanceOfCall {
    account: address!("9737100D2F42a196DE56ED0d1f6fF598a250E7E4"),
};

/// Address of the deployed contract to call the function on (USDT contract on Sepolia).
const CONTRACT: Address = address!("aA8E23Fb1079EA71e0a56F48a2aA51851D8433D0");
/// Address of the caller.
const CALLER: Address = address!("f08A50178dfcDe18524640EA6618a1f965821715");

/// Simple program to show the use of Ethereum contract data inside the guest.
#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    /// URL of the RPC endpoint
    #[arg(short, long, env = "RPC_URL")]
    rpc_url: String,

    /// Signing key of account to prove balance
    #[arg(short, long, env = "SIGNING_KEY")]
    signing_key: String,
}

fn main() -> Result<()> {
    // Initialize tracing. In order to view logs, run `RUST_LOG=info cargo run`
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    // Parse the command line arguments.
    let args = Args::parse();

    // ------------------------------------------------------------------------
    // Setting up: Locally signed message
    // ------------------------------------------------------------------------

    // Generate a random secp256k1 keypair and sign the message.
    let signing_key =
        SigningKey::from_bytes(args.signing_key.as_bytes().into()).expect("invalid signing key"); // Serialize with `::to_bytes()`
    let message = b"I hold enough RZ0!";
    let signature: Signature = signing_key.sign(message);

    // Guest inputs for the locally signed message
    let sig_msg_input = (
        signing_key.verifying_key().to_encoded_point(true),
        message,
        signature,
    );

    // ------------------------------------------------------------------------
    // Setting up: Steel view call
    // ------------------------------------------------------------------------

    // Create an EVM environment from an RPC endpoint and a block number. If no block number is
    // provided, the latest block is used.
    let mut env = EthEvmEnv::from_rpc(&args.rpc_url, None)?;
    //  The `with_chain_spec` method is used to specify the chain configuration.
    env = env.with_chain_spec(&ETH_SEPOLIA_CHAIN_SPEC);

    let commitment = env.block_commitment();

    // Preflight the call to prepare the input that is required to execute the function in
    // the guest without RPC access. It also returns the result of the call.
    let mut contract = Contract::preflight(CONTRACT, &mut env);
    let returns = contract.call_builder(&CALL).from(CALLER).call()?;
    println!(
        "For block {} `{}` returns: {}",
        env.header().number(),
        IERC20::balanceOfCall::SIGNATURE,
        returns._0
    );

    // Finally, construct the input from the environment.
    let evm_input = env.into_input()?;

    // ------------------------------------------------------------------------
    // Takeoff: Execution & Proof generation
    // ------------------------------------------------------------------------

    println!("Running the guest with the constructed input and locally signed message:");
    let session_info = {
        let env = ExecutorEnv::builder()
            .write(&evm_input)
            .unwrap()
            .write(&sig_msg_input)
            .unwrap()
            .build()
            .context("Failed to build exec env")?;
        let exec = default_executor();
        exec.execute(env, ERC20_GUEST_ELF)
            .context("failed to run executor")?
    };

    // FIXME: no proof, execution only!

    // ------------------------------------------------------------------------
    // Stick the landing: Test our assumptions and constrains hold
    // ------------------------------------------------------------------------

    // FIXME how to use mix serial and bytes parsing?
    let (local_verifying_key, receipt_message, evm_committed_bytes): (
        EncodedPoint,
        Vec<u8>,
        Vec<u8>, // FIXME what type?
    ) = session_info.journal.decode().unwrap();

    println!(
        "Verified the signature over message {:?} with key {}",
        std::str::from_utf8(&receipt_message[..]).unwrap(),
        local_verifying_key,
    );

    // The commitment in the journal should match.
    // let bytes = session_info.journal.as_ref();
    assert!(evm_committed_bytes.starts_with(&commitment.abi_encode()));

    Ok(())
}
