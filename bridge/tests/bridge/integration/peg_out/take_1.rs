use std::time::Duration;

use bitcoin::{Address, Amount, OutPoint};
use bridge::{
    connectors::base::TaprootConnector,
    graphs::{
        base::{DUST_AMOUNT, FEE_AMOUNT, INITIAL_AMOUNT, MESSAGE_COMMITMENT_FEE_AMOUNT},
        peg_out::CommitmentMessageId,
    },
    scripts::generate_pay_to_pubkey_script_address,
    superblock::{get_superblock_hash_message, get_superblock_message},
    transactions::{
        base::{BaseTransaction, Input},
        kick_off_2::{KickOff2Transaction, MIN_RELAY_FEE_AMOUNT},
        pre_signed_musig2::PreSignedMusig2Transaction,
        signing_winternitz::WinternitzSigningInputs,
        take_1::Take1Transaction,
    },
};
use tokio::time::sleep;

use crate::bridge::{
    faucet::{Faucet, FaucetType},
    helper::{get_superblock_header, verify_funding_inputs},
    integration::peg_out::utils::{
        create_and_mine_kick_off_1_tx, create_and_mine_peg_in_confirm_tx,
    },
    setup::setup_test,
};

#[tokio::test]
async fn test_take_1_success() {
    let config = setup_test().await;
    let faucet = Faucet::new(FaucetType::EsploraRegtest);

    // verify funding inputs
    let mut funding_inputs: Vec<(&Address, Amount)> = vec![];

    let deposit_input_amount = Amount::from_sat(INITIAL_AMOUNT + 2 * FEE_AMOUNT);
    let peg_in_confirm_funding_address = config.connector_z.generate_taproot_address();
    funding_inputs.push((&peg_in_confirm_funding_address, deposit_input_amount));

    let kick_off_1_input_amount = Amount::from_sat(
        3 * DUST_AMOUNT + 2 * MESSAGE_COMMITMENT_FEE_AMOUNT + FEE_AMOUNT + MIN_RELAY_FEE_AMOUNT,
    );
    let kick_off_1_funding_utxo_address = config.connector_6.generate_taproot_address();
    funding_inputs.push((&kick_off_1_funding_utxo_address, kick_off_1_input_amount));
    faucet
        .fund_inputs(&config.client_0, &funding_inputs)
        .await
        .wait()
        .await;

    verify_funding_inputs(&config.client_0, &funding_inputs).await;

    // peg-in confirm
    let (peg_in_confirm_tx, peg_in_confirm_txid) = create_and_mine_peg_in_confirm_tx(
        &config.client_0,
        &config.depositor_context,
        &config.verifier_0_context,
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_z,
        &peg_in_confirm_funding_address,
        deposit_input_amount,
    )
    .await;

    // kick-off 1
    let (kick_off_1_tx, kick_off_1_txid) = create_and_mine_kick_off_1_tx(
        &config.client_0,
        &config.operator_context,
        &kick_off_1_funding_utxo_address,
        &config.connector_1,
        &config.connector_2,
        &config.connector_6,
        kick_off_1_input_amount,
        &config.commitment_secrets,
    )
    .await;

    // kick-off 2
    let vout = 1; // connector 1
    let kick_off_2_input_0 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let mut kick_off_2 = KickOff2Transaction::new(
        &config.operator_context,
        &config.connector_1,
        kick_off_2_input_0,
    );
    let superblock_header = get_superblock_header();
    kick_off_2.sign(
        &config.operator_context,
        &config.connector_1,
        &WinternitzSigningInputs {
            message: &get_superblock_message(&superblock_header),
            signing_key: &config.commitment_secrets[&CommitmentMessageId::Superblock],
        },
        &WinternitzSigningInputs {
            message: &get_superblock_hash_message(&superblock_header),
            signing_key: &config.commitment_secrets[&CommitmentMessageId::SuperblockHash],
        },
    );
    let kick_off_2_tx = kick_off_2.finalize();
    let kick_off_2_txid = kick_off_2_tx.compute_txid();

    // mine kick-off 2
    let kick_off_2_wait_timeout = Duration::from_secs(20);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting kick-off 2 tx...",
        kick_off_2_wait_timeout
    );
    sleep(kick_off_2_wait_timeout).await;
    let kick_off_2_result = config.client_0.esplora.broadcast(&kick_off_2_tx).await;
    println!("Broadcast result: {:?}\n", kick_off_2_result);
    assert!(kick_off_2_result.is_ok());

    // take 1
    let vout = 0; // connector 0
    let take_1_input_0 = Input {
        outpoint: OutPoint {
            txid: peg_in_confirm_txid,
            vout,
        },
        amount: peg_in_confirm_tx.output[vout as usize].value,
    };
    let vout = 0; // connector a
    let take_1_input_1 = Input {
        outpoint: OutPoint {
            txid: kick_off_1_txid,
            vout,
        },
        amount: kick_off_1_tx.output[vout as usize].value,
    };
    let vout = 0; // connector 3
    let take_1_input_2 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };
    let vout = 1; // connector b
    let take_1_input_3 = Input {
        outpoint: OutPoint {
            txid: kick_off_2_txid,
            vout,
        },
        amount: kick_off_2_tx.output[vout as usize].value,
    };

    let mut take_1 = Take1Transaction::new(
        &config.operator_context,
        &config.connector_0,
        &config.connector_3,
        &config.connector_a,
        &config.connector_b,
        take_1_input_0,
        take_1_input_1,
        take_1_input_2,
        take_1_input_3,
    );

    let secret_nonces_0 = take_1.push_nonces(&config.verifier_0_context);
    let secret_nonces_1 = take_1.push_nonces(&config.verifier_1_context);

    take_1.pre_sign(
        &config.verifier_0_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_0,
    );
    take_1.pre_sign(
        &config.verifier_1_context,
        &config.connector_0,
        &config.connector_b,
        &secret_nonces_1,
    );

    let take_1_tx = take_1.finalize();
    let take_1_txid = take_1_tx.compute_txid();

    // mine take 1
    let take_1_wait_timeout = Duration::from_secs(20);
    println!(
        "Waiting \x1b[37;41m{:?}\x1b[0m before broadcasting take 1 tx...",
        take_1_wait_timeout
    );
    sleep(take_1_wait_timeout).await;
    let take_1_result = config.client_0.esplora.broadcast(&take_1_tx).await;
    println!("Broadcast result: {:?}\n", take_1_result);
    assert!(take_1_result.is_ok());

    // operator balance
    let operator_address = generate_pay_to_pubkey_script_address(
        config.operator_context.network,
        &config.operator_context.operator_public_key,
    );
    let operator_utxos = config
        .client_0
        .esplora
        .get_address_utxo(operator_address.clone())
        .await
        .unwrap();
    let operator_utxo = operator_utxos
        .clone()
        .into_iter()
        .find(|x| x.txid == take_1_txid);

    // assert
    assert!(operator_utxo.is_some());
}