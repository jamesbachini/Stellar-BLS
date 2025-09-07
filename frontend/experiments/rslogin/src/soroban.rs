use soroban_client::{network::Network, rpc::SorobanRpc, utils::transaction};
use stellar_sdk::{
    soroban::{self, contract_function},
    types::Asset,
    Network as StellarNetwork, SecretKey, Transaction, TransactionEnvelope,
};
use crate::ring::Ring;

const CONTRACT_ID: &str = "CB3M4D6WDUQKNUHMD76QTEEF6H46J7RDKKSY7YL5RV2U5T6A3NS45WT6";

pub async fn init_if_needed(
    rpc: &SorobanRpc,
    operator: &SecretKey,
    ring: &Ring,
) -> anyhow::Result<()> {
    // simple: try to read login_count; if that fails the contract isn’t initialised yet
    let sim = rpc
        .simulate()
        .invoke_contract(CONTRACT_ID, "get_login_count", ())
        .simulate()
        .await;

    if sim.is_ok() {
        return Ok(()); // already done
    }

    // --------------------------------------------------------------------------
    // build invoke tx for `init(Vec<BytesN<96>>)`
    let network = Network::new_test();
    let pk_bytes = ring.pk_bytes()
                       .into_iter()
                       .map(|b| b.to_array().to_vec() )
                       .collect::<Vec<_>>();

    let tx = rpc
        .transaction_builder(operator.public_key().clone())?
        .invoke_contract(CONTRACT_ID, "init", (pk_bytes,))
        .build()?;

    let mut envelope = transaction::sign(tx, &[operator], &network)?;
    rpc.send_and_wait(&mut envelope).await?;
    Ok(())
}