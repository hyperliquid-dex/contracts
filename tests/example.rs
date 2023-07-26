// This integration test spins up local tendermint, abci, and hardhat servers.
//
// NOTE: This does not compile without all Chameleon Trading rust dependencies.
//
// run_bridge_watcher monitors the old bridge that will be phased out
// run_bridge_watcher2 monitors the current bridge being audited
// Replicator, HyperAbci, *Action, and other unexplained things relate to the L1,
// so please take those as black boxes that work.
//
// The most relevant tests that isolate the bridge being audited are the bridge2_* tests.
//
// Note that bridge_watcher2 is a task that polls for events emitted by Bridge2 and sends the
// required validator set update and finalization transactions.
// See Bridge2.sol and tests/bridge_watcher2.rs for details.

use crate::prelude::*;
use crate::{
    abci_state::AbciStateBuilder,
    action::{owner_mint_token_for::OwnerMintTokenForAction, token_delegate::TokenDelegateAction},
    bridge2::{
        finalize_validator_set_update, sign_and_update_validator_set, SolValidatorSet, SolValidatorSetUpdate,
        ValidatorProfile, WithdrawalVoucher2,
    },
    bridge_watcher2::spawn as spawn_bridge_watcher2,
    cancel_response::{FCancelResponse, FCancelStatus},
    etherscan_tx_tracker::TXS,
    hyper_abci::{HyperAbci, ReplicaAbciCmd},
    order_response::{FOrderResponse, FOrderStatus},
    replicator::DbInit,
    run_web_server::WebServerConfig,
    signed_action::FSignedActionSuccess,
    tendermint_init::{TendermintHome, TendermintInit},
};
use ethers::prelude::k256::ecdsa::SigningKey;
use infra::{set, shell};
use std::sync::atomic::AtomicBool;
use ethers::abi::Tokenizable;

#[tokio::test]
async fn integration_tests() {
    if tu::ci() {
        return;
    }
    let recver = setup().await;
    EthClient::skip_api_validation();

    let chain = Chain::Local;
    let http_client = Arc::new(HttpClient::new(Some(ApiUrl::localhost(3002))));
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    let user_eth_client = chain.eth_client(Nickname::User).await;
    owner_eth_client.send_eth(user_eth_client.address(), 1.).await.unwrap();
    let user_eth_client = chain.eth_client(Nickname::User).await;
    owner_eth_client.send_eth(user_eth_client.address(), 1.).await.unwrap();
    owner_eth_client.send_eth(tu::main_validator_hot_user().to_address(), 1.).await.unwrap();

    let db_hub = DbHub::test();
    let replicator = Arc::new(
        ReplicatorBuilder::new(
            db_hub.clone(),
            DbInit::Legacy,
            AbciStateBuilder::New { chain }.build(),
            Some(tu::aux_core()),
            Ipv4Addr::LOCALHOST,
            recver,
        )
        .build()
        .await,
    );

    {
        let replicator = Arc::clone(&replicator);
        tokio::spawn(async move {
            setup_web_server(db_hub, replicator).await;
        });
    }
    let tx_batcher = Arc::new(TxBatcher::new(Ipv4Addr::LOCALHOST).await);
    spawn_bridge_watcher2(replicator.abci_state(), tx_batcher, true).await;

    lu::async_sleep(Duration(1.)).await;
    l1_test(&http_client).await;
    bridge_end_to_end_test(&http_client, &replicator).await;
    bridge2_end_to_end_test(&http_client, &replicator).await;
    bridge2_update_validator_tests().await;
    bridge2_withdrawal_tests().await;
    bridge2_locking_test().await;
    bridge2_batched_finalize_withdrawals_unit_tests().await;
}

async fn bridge2_end_to_end_test(http_client: &Arc<HttpClient>, replicator: &Arc<Replicator>) {
    use crate::bridge_watcher2::DepositEvent;

    let chain = Chain::Local;
    let eth_chain = chain.eth_chain();
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    assert!(replicator.lock(|e| e.has_bridge2(), "integration_test_has_bridge2"));
    lu::async_sleep(Duration(1.)).await;
    let active_epoch = replicator.lock(|e| e.staking().active_epoch(), "integration_test_active_epoch");
    assert_eq!(
        replicator.lock(
            |e| e.staking().validator_to_hot_user(tu::main_validator(), active_epoch).unwrap(),
            "integration_test_validator_to_hot_user"
        ),
        tu::main_validator_hot_user()
    );

    let amount = 10.0;
    let amount_u64 = amount.with_decimals(USDC_ERC20_DECIMALS);

    let user = User::new(owner_eth_client.address());
    let action = Box::new(OwnerMintTokenForAction { amount: 99, user });
    let owner_wallet = Nickname::Owner.wallet(chain);
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    http_client.send_signed_action(signed_action).await.unwrap().unwrap();

    let action = Box::new(TokenDelegateAction { validator: tu::main_validator(), amount: 99 });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    http_client.send_signed_action(signed_action).await.unwrap().unwrap();

    let bridge2_cid = chain.bridge2_cid();
    chain.usdc_cid().send("approve", (bridge2_cid.address(eth_chain), u64::MAX), &owner_eth_client).await.unwrap();
    let tx_receipt = bridge2_cid.send("deposit", amount_u64, &owner_eth_client).await.unwrap();
    TXS.lock().entry(bridge2_cid.address(eth_chain)).or_default().insert(tx_receipt.transaction_hash);

    lu::async_sleep(Duration(3.)).await;
    let deposit_events: Vec<DepositEvent> = owner_eth_client.parse_events(bridge2_cid, tx_receipt);
    let DepositEvent { usdc, .. } = *deposit_events.first().unwrap();
    assert_eq!(usdc.to_string(), "10000000");

    let action = Box::new(WithdrawAction { nonce: 0, usd: amount_u64 });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    http_client.send_signed_action(signed_action).await.unwrap().unwrap();

    lu::async_sleep(Duration(8.)).await;
    let claimable_withdrawals =
        replicator.lock(|e| e.claimable_withdrawals(user), "integration_test_claimable_withdrawals");
    assert!(!claimable_withdrawals.is_empty());
    let withdrawal_voucher = claimable_withdrawals.first().unwrap();
    assert_eq!(withdrawal_voucher.signers, vec![tu::main_validator_hot_user()]);
    warn!("withdrawing from bridge2" => withdrawal_voucher, active_epoch);

    // NOSHIP write test for claiming and finalizing withdrawal successfully, too early, failure on multiple times
}

async fn l1_test(http_client: &Arc<HttpClient>) {
    let chain = Chain::Local;
    let owner_wallet = Nickname::Owner.wallet(chain);
    let user_wallet = tu::wallet(1);
    let agent_wallet = tu::wallet(4);
    let req = utils::approve_agent_action(&user_wallet, &agent_wallet).unwrap();

    http_client.send_signed_action(req).await.unwrap().unwrap();

    http_client
        .send_signed_action(
            SignedAction::new(
                Box::new(RegisterAssetAction {
                    coin: "ETH".to_string(),
                    sz_decimals: 1,
                    oracle_px: 1000.,
                    max_leverage: 50,
                }),
                &owner_wallet,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();
    http_client
        .send_signed_action(
            SignedAction::new(
                Box::new(RegisterAssetAction {
                    coin: "BTC".to_string(),
                    sz_decimals: 1,
                    oracle_px: 1000.,
                    max_leverage: 50,
                }),
                &owner_wallet,
            )
            .unwrap(),
        )
        .await
        .unwrap()
        .unwrap();

    let action = tu::o(1, Side::Bid, 123400000., 1.).into_action();
    let req = SignedAction::new(action, &agent_wallet).unwrap();
    let resp = http_client.send_signed_action(req).await.unwrap().unwrap();
    let FSignedActionSuccess::Order(FOrderResponse { statuses }) = resp else {
        unreachable!("{resp:?}")
    };

    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0], FOrderStatus::Error("Insufficient margin to place order.".to_string()));

    let cancel_action = CancelAction { cancels: vec![Cancel { asset: 0, oid: 123 }] };
    let req = SignedAction::new(Box::new(cancel_action), &agent_wallet).unwrap();
    let resp = http_client.send_signed_action(req).await.unwrap().unwrap();
    let FSignedActionSuccess::Cancel(FCancelResponse { statuses }) = resp else {
        unreachable!("{resp:?}")
    };

    assert_eq!(statuses.len(), 1);
    assert!(
        u::serde_eq(
            &statuses[0],
            &FCancelStatus::Error("Order was never placed, already canceled, or filled.".to_string())
        ),
        "{statuses:?}"
    );
}

async fn bridge2_update_validator_tests() {
    // NOSHIP test validator set updates with cold keys different than hot keys
    let chain = Chain::Local;
    let eth_chain = chain.eth_chain();
    let eth_client = tu::main_validator_eth_client().await;
    let wallet0 = tu::main_validator_hot_wallet();
    let wallet1 = tu::wallet(1);
    let wallet2 = tu::wallet(2);

    let user0 = tu::main_validator_hot_user();
    let user1 = wallet1.address().into();
    let user2 = wallet2.address().into();

    warn!("running bridge2_update_validator_tests" => user0, user1, user2, eth_client.address());
    let cur_epoch: u64 = chain.bridge2_cid().call("epoch", (), &eth_client).await.unwrap();
    let new_epoch = cur_epoch + 1;
    let active_validator_set = initial_validator_set();
    let new_validator_set = set![
        ValidatorProfile { power: 50, hot_user: user0, cold_user: user0 },
        ValidatorProfile { power: 50, hot_user: user1, cold_user: user1 }
    ];
    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        &[wallet0.clone()],
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();

    let cur_epoch = new_epoch;
    let new_epoch = cur_epoch + 1;
    let active_validator_set = new_validator_set;
    let new_validator_set = set![
        ValidatorProfile { power: 50, hot_user: user0, cold_user: user0 },
        ValidatorProfile { power: 25, hot_user: user1, cold_user: user1 },
        ValidatorProfile { power: 25, hot_user: user2, cold_user: user2 },
    ];
    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        &[wallet0.clone(), wallet1.clone()],
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();

    let amount = 10.0;
    let usd = amount.with_decimals(USDC_ERC20_DECIMALS);
    let nonce = 0;
    let hash = utils::keccak((user0.raw(), usd, nonce));
    let signatures = vec![chain.sign_phantom_agent(hash, &wallet0)];
    let withdrawal_voucher_no_quorum = WithdrawalVoucher2 {
        usd,
        nonce,
        active_validator_set: new_validator_set.clone(),
        signers: vec![user0],
        signatures,
    };

    let res = tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher_no_quorum, new_epoch).await;
    tu::assert_err(res, "Submitted validator set signatures do not have enough power");

    chain.usdc_cid().send("approve", (chain.bridge2_cid().address(eth_chain), u64::MAX), &eth_client).await.unwrap();
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    chain.usdc_cid().send("transfer", (user0.raw(), usd), &owner_eth_client).await.unwrap();
    chain.bridge2_cid().send("deposit", usd, &eth_client).await.unwrap();

    let cur_epoch = new_epoch;
    let new_epoch = cur_epoch + 1;
    let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(new_epoch, &new_validator_set);
    let sol_active_validator_set = SolValidatorSet::from_hot_validator_set(cur_epoch, &active_validator_set);
    let sol_new_validator_set_hash = sol_new_validator_set.hash();
    let mut signatures = Vec::new();
    for validator in [&wallet0, &wallet1, &wallet2] {
        signatures.push(chain.sign_phantom_agent(sol_new_validator_set_hash, validator));
    }
    let signers: Vec<_> = active_validator_set.iter().rev().map(|x| x.hot_user.raw()).collect();
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (sol_new_validator_set.clone(), sol_active_validator_set.clone(), signers, signatures.clone()),
            &eth_client,
        )
        .await;

    tu::assert_err(res, "Supplied active validators and powers do not match checkpoint");

    let active_validator_set = set![
        ValidatorProfile { power: 50, hot_user: user0, cold_user: user0 },
        ValidatorProfile { power: 25, hot_user: user1, cold_user: user1 },
        ValidatorProfile { power: 25, hot_user: user2, cold_user: user2 },
    ];
    let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(cur_epoch, &active_validator_set);
    let sol_active_validator_set = SolValidatorSet::from_hot_validator_set(cur_epoch, &active_validator_set);
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (
                sol_new_validator_set.clone(),
                sol_active_validator_set.clone(),
                sol_active_validator_set.validators.clone(),
                signatures.clone(),
            ),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "New validator set epoch must be greater than the active epoch");

    let mut wrong_signatures = Vec::new();
    for validator in &[&wallet1, &wallet2, &wallet2] {
        wrong_signatures.push(chain.sign_phantom_agent(sol_new_validator_set.hash(), validator));
    }
    let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(new_epoch, &active_validator_set);
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (
                sol_new_validator_set.clone(),
                sol_active_validator_set.clone(),
                sol_active_validator_set.validators.clone(),
                wrong_signatures,
            ),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Validator signature does not match");

    let no_quorum_signatures = vec![chain.sign_phantom_agent(sol_new_validator_set.hash(), &wallet1)];
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (sol_new_validator_set, sol_active_validator_set.clone(), vec![user1.raw()], no_quorum_signatures),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Submitted validator set signatures do not have enough power");

    let new_validator_wallets = utils::wallet_range(100);
    let new_validator_set = new_validator_wallets
        .iter()
        .enumerate()
        .map(|(u, wallet)| ValidatorProfile {
            power: (100 - u) as u64,
            hot_user: wallet.address().into(),
            cold_user: wallet.address().into(),
        })
        .collect();
    let active_validator_set = set![
        ValidatorProfile { power: 50, hot_user: user0, cold_user: user0 },
        ValidatorProfile { power: 25, hot_user: user1, cold_user: user1 },
        ValidatorProfile { power: 25, hot_user: user2, cold_user: user2 },
    ];
    let wallets = [wallet0.clone(), wallet1.clone(), wallet2.clone()];
    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        &wallets,
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();

    let cur_epoch = new_epoch;
    let new_epoch = cur_epoch + 1;
    let active_validator_set = new_validator_set;
    let new_validator_set = initial_validator_set();
    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        new_validator_wallets.as_slice(),
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();
}

async fn bridge_end_to_end_test(http_client: &Arc<HttpClient>, replicator: &Arc<Replicator>) {
    use crate::bridge_watcher::DepositEvent;
    warn!("starting bridge_end_to_end_test");
    let chain = Chain::Local;
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    let user_eth_client = chain.eth_client(Nickname::User).await;

    let initial_account_value = account_value(replicator, User::new(owner_eth_client.address()));
    let amount = 11.;
    let owner_usdc_amount = (5. * amount).with_decimals(USDC_ERC20_DECIMALS);
    let user_usdc_amount = (3. * amount).with_decimals(USDC_ERC20_DECIMALS);

    let bridge_cid = chain.bridge_cid();
    chain.usdc_cid().send("mint", owner_usdc_amount + user_usdc_amount, &owner_eth_client).await.unwrap();
    chain.usdc_cid().send("transfer", (user_eth_client.address(), user_usdc_amount), &owner_eth_client).await.unwrap();
    chain
        .usdc_cid()
        .send("approve", (bridge_cid.address(owner_eth_client.chain()), owner_usdc_amount), &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send("approve", (bridge_cid.address(owner_eth_client.chain()), user_usdc_amount), &user_eth_client)
        .await
        .unwrap();

    let initial_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(initial_owner_usdc_balance, owner_usdc_amount);
    let initial_not_owner_eth_client_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", user_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(initial_not_owner_eth_client_usdc_balance, user_usdc_amount);
    let initial_user_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", user_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(initial_user_usdc_balance, user_usdc_amount);

    let bridge_cid = chain.bridge_cid();
    let tx_receipt =
        bridge_cid.send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.clone().transaction_hash;
    TXS.lock().entry(bridge_cid.address(chain.eth_chain())).or_default().insert(tx_hash);

    let tx_receipt =
        bridge_cid.send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.clone().transaction_hash;
    TXS.lock().entry(bridge_cid.address(chain.eth_chain())).or_default().insert(tx_hash);

    lu::async_sleep(Duration(5.)).await;

    let deposit_events: Vec<DepositEvent> = owner_eth_client.parse_events(bridge_cid, tx_receipt);
    let DepositEvent { user, usdc, .. } = *deposit_events.first().unwrap();
    assert_eq!(usdc.to_string(), "11000000");
    assert_eq!(user, owner_eth_client.address().raw());
    let final_account_value = account_value(replicator, User::new(owner_eth_client.address()));

    warn!("should have deposited" => initial_account_value, final_account_value, owner_eth_client.address(), deposit_events);
    assert_eq!(final_account_value - initial_account_value, 2. * amount);
    let initial_account_value = account_value(replicator, User::new(owner_eth_client.address()));

    let nonce = 1;
    let withdraw_amount = 10.;
    let usd = withdraw_amount.with_decimals(USDC_ERC20_DECIMALS);
    let withdraw_action = WithdrawAction { usd, nonce };

    let signing_key = SigningKey::from_bytes(&owner_eth_client.key().to_fixed_bytes()).unwrap();
    let owner_wallet = Wallet::from(signing_key);
    let owner_agent = tu::wallet(5);
    let req = utils::approve_agent_action(&owner_wallet, &owner_agent).unwrap();
    http_client.send_signed_action(req).await.unwrap().unwrap();

    let req = SignedAction::new(Box::new(withdraw_action), &owner_agent).unwrap();
    http_client.send_signed_action(req).await.unwrap().unwrap();

    let owner = User::new(owner_eth_client.address());
    let final_account_value = account_value(replicator, owner);
    assert_eq!(initial_account_value - final_account_value, withdraw_amount);

    let mut pending_withdrawals = replicator
        .lock(|e| e.bridge().pending_withdrawals(owner).unwrap().clone(), "integration_test_pending_withdrawals");
    assert!(pending_withdrawals.len() == 1);
    let withdrawal_voucher = pending_withdrawals.pop().unwrap();
    warn!("pending withdrawal" => withdrawal_voucher);

    let mut incorrect_amount_voucher = withdrawal_voucher.clone();
    incorrect_amount_voucher.action.usd = 1000.0.with_decimals(USDC_ERC20_DECIMALS);
    let res = claim_withdrawal_on_bridge(chain, incorrect_amount_voucher, &owner_eth_client).await;
    assert!(res.err().unwrap().to_string().contains("Withdrawal not signed by Hyperliquid."));

    let tx_receipt = claim_withdrawal_on_bridge(chain, withdrawal_voucher.clone(), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.transaction_hash;
    TXS.lock().entry(bridge_cid.address(chain.eth_chain())).or_default().insert(tx_hash);

    let res = claim_withdrawal_on_bridge(chain, withdrawal_voucher, &owner_eth_client).await;
    assert!(res.err().unwrap().to_string().contains("Already withdrawn."));

    lu::async_sleep(Duration(2.)).await;

    let pending_withdrawals = replicator
        .lock(|e| e.bridge().pending_withdrawals(owner).unwrap().clone(), "integration_test_pending_withdrawals");
    warn!("should have no pending withdrawals" => owner, pending_withdrawals);

    let is_locked: bool = bridge_cid.call("isLocked", (), &owner_eth_client).await.unwrap();
    assert!(!is_locked);
    let res = bridge_cid.send("setIsLocked", true, &user_eth_client).await;
    tu::assert_err(res, "Ownable: caller is not the owner");
    bridge_cid.send("setIsLocked", true, &owner_eth_client).await.unwrap();
    let is_locked: bool = bridge_cid.call("isLocked", (), &owner_eth_client).await.unwrap();
    assert!(is_locked);

    let nonce = 2;
    let usd = 1.0.with_decimals(USDC_ERC20_DECIMALS);
    let withdraw_action = WithdrawAction { usd, nonce };
    let req = SignedAction::new(Box::new(withdraw_action), &owner_agent).unwrap();
    http_client.send_signed_action(req).await.unwrap().unwrap();
    let mut pending_withdrawals = replicator
        .lock(|e| e.bridge().pending_withdrawals(owner).unwrap().clone(), "integration_test_pending_withdrawals");
    let withdrawal_voucher = pending_withdrawals.pop().unwrap();
    let res = claim_withdrawal_on_bridge(chain, withdrawal_voucher, &owner_eth_client).await;
    tu::assert_err(res, "Cannot withdraw/deposit from/to locked bridge");

    let res = bridge_cid.send("withdrawAllUsdcToOwner", (), &user_eth_client).await;
    tu::assert_err(res, "Ownable: caller is not the owner");
    let bridge_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", bridge_cid.address(EthChain::Localhost), &owner_eth_client).await.unwrap();
    let old_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    bridge_cid.send("withdrawAllUsdcToOwner", (), &owner_eth_client).await.unwrap();
    let new_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(new_owner_usdc_balance, old_owner_usdc_balance + bridge_usdc_balance);

    assert!(pending_withdrawals.is_empty());

    bridge_cid.send("setIsLocked", false, &owner_eth_client).await.unwrap();
    bridge_cid.send("setWhitelistOnly", true, &owner_eth_client).await.unwrap();
    let res = bridge_cid.send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &user_eth_client).await;
    tu::assert_err(res, "Sender is not whitelisted");
    bridge_cid
        .send("setUsersWhitelistState", (vec![user_eth_client.address().raw()], true), &owner_eth_client)
        .await
        .unwrap();
    bridge_cid.send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &user_eth_client).await.unwrap();

    bridge_cid
        .send("setMaxDepositPerPeriod", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client)
        .await
        .unwrap();
    let seconds_per_deposit_period: u64 = 24 * 60 * 60;
    bridge_cid.send("setSecondsPerDepositPeriod", seconds_per_deposit_period, &owner_eth_client).await.unwrap();
    let receipt =
        bridge_cid.send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &user_eth_client).await.unwrap();
    let timestamp = user_eth_client.receipt_to_block(&receipt).await.unwrap().timestamp.without_decimals(0);

    let amount_deposited_this_period: u64 = bridge_cid
        .call(
            "amountDepositedPerPeriod",
            (timestamp as u64 / seconds_per_deposit_period, user_eth_client.address().raw()),
            &user_eth_client,
        )
        .await
        .unwrap();
    assert_eq!(amount_deposited_this_period, amount.with_decimals(USDC_ERC20_DECIMALS));
    let res = bridge_cid.send("deposit", (0.5 * amount).with_decimals(USDC_ERC20_DECIMALS), &user_eth_client).await;
    tu::assert_err(res, "deposit amount exceeds the maximum for this period");

    let usd = account_value(replicator, owner).with_decimals(USDC_ERC20_DECIMALS);
    let withdraw_action = WithdrawAction { usd, nonce };
    let signed_action = SignedAction::new(Box::new(withdraw_action), &owner_agent).unwrap();
    http_client.send_signed_action(signed_action).await.unwrap().unwrap();
    assert_eq!(replicator.lock(|e| e.bridge().bal, "integration_test_bridge_bal"), 0);

    TXS.lock().clear();
}

async fn bridge2_withdrawal_tests() {
    let chain = Chain::Local;
    let eth_client = tu::main_validator_eth_client().await;
    let hot_user = tu::main_validator_hot_user();
    let hot_wallet = tu::main_validator_hot_wallet();

    let powers = vec![55, 20, 10, 10, 6, 5, 3, 2, 1, 1];
    let wallets = utils::wallet_range(10);
    let tot_power: u64 = powers.iter().sum();

    let active_validator_set = initial_validator_set();
    let cur_epoch: u64 = chain.bridge2_cid().call("epoch", (), &eth_client).await.unwrap();
    let new_epoch = cur_epoch + 1;
    let new_validator_set: Set<_> = wallets
        .iter()
        .enumerate()
        .map(|(i, wallet)| ValidatorProfile {
            power: powers[i],
            hot_user: wallet.address().into(),
            cold_user: tu::user((1000 + i) as u8),
        })
        .collect();

    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        &[hot_wallet],
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();
    let cur_epoch = new_epoch;

    let mut nonce = 0;
    let usd = 1.0.with_decimals(USDC_ERC20_DECIMALS);
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    chain.usdc_cid().send("transfer", (hot_user.raw(), 30 * usd), &owner_eth_client).await.unwrap();
    chain.bridge2_cid().send("deposit", 30 * usd, &eth_client).await.unwrap();

    let active_validator_set = new_validator_set;
    for inds in [
        Vec::new(),
        vec![0],
        vec![3],
        vec![9],
        vec![1, 2, 3, 4, 5, 6],
        vec![0, 3, 6, 8],
        vec![6, 7],
        vec![0, 4, 8, 9],
        vec![0, 1, 2, 5, 6, 9],
        vec![1, 2, 6],
        vec![2, 3, 6, 7, 9],
        vec![0, 1, 4, 5, 9],
        vec![0, 5, 7, 8],
        vec![0, 1, 2, 3, 5, 7, 8],
        vec![1, 3, 6, 9],
        vec![1, 2, 4, 5, 7, 8, 9],
        vec![4, 6, 8],
        vec![0, 1, 2, 4, 5, 6, 9],
        vec![1, 2, 3, 7, 8, 9],
        vec![1, 4, 5, 6, 7, 8, 9],
        vec![0, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![0, 2, 3, 7, 9],
        vec![2, 4, 5, 6, 7, 8],
        vec![0, 1, 3, 5, 6, 7, 9],
        vec![0, 5, 7, 8, 9],
        vec![0, 2, 4, 5, 7, 9],
        vec![0, 2, 5],
        vec![0, 1, 3, 4, 6, 7, 9],
        vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    ] {
        let mut tot_sample_power = 0;
        let mut signatures = Vec::new();
        let mut signers = Vec::new();
        let mut sample_powers = Vec::new();
        let hash = utils::keccak((hot_user.raw(), usd, nonce));

        for &i in &inds {
            let wallet = &wallets[i];
            let power = powers[i];
            signatures.push(chain.sign_phantom_agent(hash, wallet));
            signers.push(wallet.address().into());
            tot_sample_power += power;
            sample_powers.push(power);
        }

        let quorum_reached = 3 * tot_sample_power >= 2 * tot_power;
        warn!("withdrawal fuzz test working on" => inds, quorum_reached);

        let withdrawal_voucher =
            WithdrawalVoucher2 { usd, nonce, signers, active_validator_set: active_validator_set.clone(), signatures };
        nonce += 1;

        let res = tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher, cur_epoch).await;
        assert_eq!(res.is_ok(), quorum_reached, "inds={inds:?} res={res:?}");
    }

    // return to state that the node integration test can use
    let new_epoch = cur_epoch + 1;
    let new_validator_set = initial_validator_set();
    sign_and_update_validator_set(
        &eth_client,
        chain,
        &active_validator_set,
        &new_validator_set,
        cur_epoch,
        new_epoch,
        wallets.as_slice(),
    )
    .await
    .unwrap();
    finalize_validator_set_update(&eth_client, chain).await.unwrap();
}

async fn bridge2_locking_test() {
    let chain = Chain::Local;

    let eth_client = tu::main_validator_eth_client().await;
    let hot_user = tu::main_validator_hot_user();
    let hot_wallet = tu::main_validator_hot_wallet();
    let cold_wallet = tu::main_validator_cold_wallet();
    let cold_user = tu::main_validator_cold_user();

    let cur_epoch: u64 = chain.bridge2_cid().call("epoch", (), &eth_client).await.unwrap();
    let active_validator_set = initial_validator_set();

    let sol_active_hot_valdiator_set = SolValidatorSet::from_hot_validator_set(cur_epoch, &active_validator_set);
    let unauthorized_locker = chain.eth_client(Nickname::User).await;
    let res = chain.bridge2_cid().send("emergencyLock", (), &unauthorized_locker).await;
    tu::assert_err(res, "Sender is not authorized to lock smart contract");

    let locker = hot_user.raw();
    let is_locker = true;
    let nonce = U256::zero();
    let hash = utils::keccak(("modifyLocker".to_string(), locker, is_locker, nonce));
    let signer = hot_user.raw();
    let signature = chain.sign_phantom_agent(hash, &hot_wallet);
    chain
        .bridge2_cid()
        .send(
            "modifyLocker",
            (locker, is_locker, nonce, sol_active_hot_valdiator_set.clone(), vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();
    let res: bool = chain.bridge2_cid().call("isLocker", locker, &eth_client).await.unwrap();
    assert_eq!(res, is_locker);

    let user1 = tu::user(1);
    let finalizer = user1.raw();
    let is_finalizer = true;
    let nonce = U256::zero();
    let hash = utils::keccak(("modifyFinalizer".to_string(), finalizer, is_finalizer, nonce));
    let signer = hot_user.raw();
    let signature = chain.sign_phantom_agent(hash, &hot_wallet);
    chain
        .bridge2_cid()
        .send(
            "modifyFinalizer",
            (finalizer, is_finalizer, nonce, sol_active_hot_valdiator_set.clone(), vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();
    let res: bool = chain.bridge2_cid().call("isFinalizer", finalizer, &eth_client).await.unwrap();
    assert_eq!(res, is_finalizer);

    chain.bridge2_cid().send("emergencyLock", (), &eth_client).await.unwrap();

    let signer = cold_user.raw();
    let new_dispute_period_seconds = U256::from(10);
    let nonce = U256::zero();
    let sol_active_cold_validator_set = SolValidatorSet::from_cold_validator_set(cur_epoch, &active_validator_set);
    let hash = utils::keccak(("changeDisputePeriodSeconds".to_string(), new_dispute_period_seconds, nonce));
    let signature = chain.sign_phantom_agent(hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "changeDisputePeriodSeconds",
            (new_dispute_period_seconds, nonce, sol_active_cold_validator_set.clone(), vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();

    let res: U256 = chain.bridge2_cid().call("disputePeriodSeconds", (), &eth_client).await.unwrap();
    assert_eq!(res, new_dispute_period_seconds);

    let new_block_duration_millis = U256::from(200);
    let hash = utils::keccak(("changeBlockDurationMillis".to_string(), new_block_duration_millis, nonce));
    let signature = chain.sign_phantom_agent(hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "changeBlockDurationMillis",
            (new_block_duration_millis, nonce, sol_active_cold_validator_set.clone(), vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();

    let res: U256 = chain.bridge2_cid().call("blockDurationMillis", (), &eth_client).await.unwrap();
    assert_eq!(res, new_block_duration_millis);

    let new_epoch = cur_epoch + 1;
    let new_validator_set = initial_validator_set();
    let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(new_epoch, &new_validator_set);
    let nonce = U256::zero();
    let hash = utils::keccak((
        "unlock".to_string(),
        sol_new_validator_set.epoch,
        sol_new_validator_set.clone().hot_addresses,
        sol_new_validator_set.clone().cold_addresses,
        sol_new_validator_set.clone().powers,
        nonce,
    ));
    let signature = chain.sign_phantom_agent(hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "emergencyUnlock",
            (sol_new_validator_set, sol_active_cold_validator_set, vec![signer], vec![signature], nonce),
            &eth_client,
        )
        .await
        .unwrap();

    let cur_epoch = new_epoch;
    let active_validator_set = new_validator_set;
    let sol_active_cold_valdiator_set = SolValidatorSet::from_cold_validator_set(cur_epoch, &active_validator_set);
    let locker = hot_user.raw();
    let is_locker = false;
    let nonce = U256::one();
    let hash = utils::keccak(("modifyLocker".to_string(), locker, is_locker, nonce));
    let signer = cold_user.raw();
    let signature = chain.sign_phantom_agent(hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "modifyLocker",
            (locker, is_locker, nonce, sol_active_cold_valdiator_set.clone(), vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();
    let res: bool = chain.bridge2_cid().call("isLocker", locker, &eth_client).await.unwrap();
    assert_eq!(res, is_locker);

    let finalizer = user1.raw();
    let is_finalizer = false;
    let nonce = U256::one();
    let hash = utils::keccak(("modifyFinalizer".to_string(), finalizer, is_finalizer, nonce));
    let signer = cold_user.raw();
    let signature = chain.sign_phantom_agent(hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "modifyFinalizer",
            (finalizer, is_finalizer, nonce, sol_active_cold_valdiator_set, vec![signer], vec![signature]),
            &eth_client,
        )
        .await
        .unwrap();
    let res: bool = chain.bridge2_cid().call("isFinalizer", finalizer, &eth_client).await.unwrap();
    assert_eq!(res, is_finalizer);
}

async fn bridge2_batched_finalize_withdrawals_unit_tests() {
    let chain = Chain::Local;
    let eth_client = tu::main_validator_eth_client().await;
    let hot_user = tu::main_validator_hot_user();
    let hot_wallet = tu::main_validator_hot_wallet();
    let cold_wallet = tu::main_validator_cold_wallet();
    let cur_epoch: u64 = chain.bridge2_cid().call("epoch", (), &eth_client).await.unwrap();
    let active_validator_set = initial_validator_set();

    let usd = 10.0.with_decimals(USDC_ERC20_DECIMALS);
    // Approve usdc and initialize bridge with sufficient funds
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    chain
        .usdc_cid()
        .send("approve", (chain.bridge2_cid().address(chain.eth_chain()), u64::MAX), &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send("approve", (chain.bridge2_cid().address(chain.eth_chain()), u64::MAX), &eth_client)
        .await
        .unwrap();
    let initial_bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    let initial_user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    let to_transfer = 30 * usd - initial_bridge_bal.as_u64();
    let to_mint = to_transfer - initial_user_bal.as_u64();
    chain.usdc_cid().send("mint", to_mint, &owner_eth_client).await.unwrap();
    chain.usdc_cid().send("transfer", (hot_user.raw(), to_mint), &owner_eth_client).await.unwrap();
    chain.bridge2_cid().send("deposit", to_transfer, &eth_client).await.unwrap();
    let bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    assert_eq!(bridge_bal, U256::from(30 * usd));
    let user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    assert_eq!(user_bal, U256::zero());

    // Set dispute period and block duration so that we can test that dispute period works.
    // The bridge must be locked to set the dispute period and block duration, which requires a locker.
    let locker = hot_user.raw();
    let is_locker = true;
    let nonce = U256::from(2);
    let hash = utils::keccak(("modifyLocker".to_string(), locker, is_locker, nonce));
    let signature = bridge2_sign_phantom_agent(chain, hash, &hot_wallet);
    chain
        .bridge2_cid()
        .send(
            "modifyLocker",
            (
                locker,
                is_locker,
                nonce,
                SolValidatorSet::from_hot_validator_set(cur_epoch, &active_validator_set),
                vec![signature],
            ),
            &eth_client,
        )
        .await
        .unwrap();

    chain.bridge2_cid().send("emergencyLock", (), &eth_client).await.unwrap();

    let sol_active_cold_validator_set = SolValidatorSet::from_cold_validator_set(cur_epoch, &active_validator_set);
    perform_bridge_2_validator_action(
        "changeDisputePeriodSeconds",
        U256::from(1),
        nonce,
        chain,
        &cold_wallet,
        &sol_active_cold_validator_set,
        &eth_client,
    )
    .await;
    perform_bridge_2_validator_action(
        "changeBlockDurationMillis",
        U256::from(1000),
        nonce,
        chain,
        &cold_wallet,
        &sol_active_cold_validator_set,
        &eth_client,
    )
    .await;

    let cur_epoch = cur_epoch + 1;
    let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(cur_epoch, &active_validator_set);
    let hash = utils::keccak((
        "unlock".to_string(),
        sol_new_validator_set.epoch,
        sol_new_validator_set.clone().hot_addresses,
        sol_new_validator_set.clone().cold_addresses,
        sol_new_validator_set.clone().powers,
        nonce,
    ));
    let signature = bridge2_sign_phantom_agent(chain, hash, &cold_wallet);
    chain
        .bridge2_cid()
        .send(
            "emergencyUnlock",
            (sol_new_validator_set, sol_active_cold_validator_set, vec![signature], nonce),
            &eth_client,
        )
        .await
        .unwrap();

    // Request withdrawal should work and produce receipt
    let nonce = 11;
    let hash = withdrawal_hash(hot_user, usd, nonce);
    let signatures = vec![bridge2_sign_phantom_agent(chain, hash, &hot_wallet)];
    let withdrawal_voucher =
        WithdrawalVoucher2 { usd, nonce, active_validator_set: active_validator_set.clone(), signatures };
    let tx_receipt = tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher, cur_epoch).await.unwrap();
    let requested_withdrawals: Vec<RequestedWithdrawalEvent> = eth_client.parse_events(chain.bridge2_cid(), tx_receipt);
    assert_eq!(requested_withdrawals.len(), 1);
    let bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    assert_eq!(bridge_bal, U256::from(30 * usd));
    let user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    assert_eq!(user_bal, U256::zero());

    // Finalizing withdrawal should fail due to dispute period
    let message = requested_withdrawals.first().unwrap().message;
    let result = chain.bridge2_cid().send("batchedFinalizeWithdrawals", vec![message], &eth_client).await;
    tu::assert_err(result, "Still in dispute period");
    let bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    assert_eq!(bridge_bal, U256::from(30 * usd));
    let user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    assert_eq!(user_bal, U256::zero());

    // Sleep for longer than dispute period and try again should succeed
    lu::async_sleep(Duration(1.)).await;
    let tx_receipt = chain.bridge2_cid().send("batchedFinalizeWithdrawals", vec![message], &eth_client).await.unwrap();
    let withdrawal_finalization_events: Vec<FinalizedWithdrawalEvent> =
        eth_client.parse_events(chain.bridge2_cid(), tx_receipt);
    assert_eq!(withdrawal_finalization_events.len(), 1);
    let bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    assert_eq!(bridge_bal, U256::from(29 * usd));
    let user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    assert_eq!(user_bal, U256::from(usd));

    // Try to finalize the same receipt should fail
    let result = chain.bridge2_cid().send("batchedFinalizeWithdrawals", vec![message], &eth_client).await;
    tu::assert_err(result, "Withdrawal already finalized");
    let bridge_bal: U256 =
        chain.usdc_cid().call("balanceOf", chain.bridge2_cid().address(chain.eth_chain()), &eth_client).await.unwrap();
    assert_eq!(bridge_bal, U256::from(29 * usd));
    let user_bal: U256 = chain.usdc_cid().call("balanceOf", hot_user.to_address(), &eth_client).await.unwrap();
    assert_eq!(user_bal, U256::from(usd));
}

fn initial_validator_set() -> Set<ValidatorProfile> {
    set![ValidatorProfile {
        power: 1,
        hot_user: tu::main_validator_hot_user(),
        cold_user: tu::main_validator_cold_user(),
    }]
}

async fn setup() -> Recver<ReplicaAbciCmd> {
    assert!(!*NODES_RUNNING.lock());
    *NODES_RUNNING.lock() = true;
    TendermintInit::Wipe.run(None, TendermintHome::Normal);
    let (sender, recver) = channel();
    let hyper_abci = HyperAbci::new(AbciStateBuilder::New { chain: Chain::Local }, sender, false, None);
    std::thread::spawn(move || hyper_abci.run_server_blocking(TendermintHome::Normal));
    spawn_hardhat_node().await;
    lu::async_sleep(Duration(1.)).await;
    recver
}

async fn setup_web_server(db_hub: Arc<DbHub>, replicator: Arc<Replicator>) {
    let localhost = Ipv4Addr::LOCALHOST;
    let (block_events_sender, block_events_recver) = channel();
    let web_server_config = WebServerConfig {
        n_nodes: Some(1),
        node_ip: localhost,
        internal_ip: localhost,
        print_requests: false,
        chain: Chain::Local,
        db_hub,
        replicator,
        block_events_sender,
        block_events_recver,
        web_server_port: 3002,
        should_run_solo_watcher: true,
        db_init: DbInit::Legacy,
        finished_seeding_explorer: Arc::new(AtomicBool::new(true)),
    };
    web_server_config.run().await;
}

async fn spawn_hardhat_node() {
    std::thread::spawn(|| {
        shell("(cd ~/cham/code/hyperliquid && npx hardhat node) > /tmp/hardhat_out 2>&1".to_string()).wait_check()
    });
    lu::async_sleep(Duration(1.)).await;
    shell("(cd ~/cham/code/hyperliquid && npx hardhat run deploy/contracts.js --network localhost) > /tmp/hardhat_deploy_out 2>&1".to_string()).wait_check();
}

fn account_value(replicator: &Replicator, user: User) -> f64 {
    replicator
        .lock(|e| e.web_data(Some(user)), "integration_test_account_value")
        .user_state
        .margin_summary
        .account_value
        .0
}

async fn claim_withdrawal_on_bridge(
    chain: Chain,
    withdrawal_voucher: WithdrawalVoucher,
    client: &EthClient,
) -> infra::Result<Receipt> {
    let WithdrawalVoucher { signature, action: WithdrawAction { usd, nonce }, .. } = withdrawal_voucher;
    chain.bridge_cid().send("withdraw", (signature, usd, nonce), client).await
}

async fn perform_bridge_2_validator_action<T: Tokenizable + Debug + Copy>(
    action: &str,
    arg: T,
    nonce: U256,
    chain: Chain,
    wallet: &Wallet,
    sol_validator_set: &SolValidatorSet,
    eth_client: &EthClient,
) {
    let hash = utils::keccak((action.to_string(), arg, nonce));
    let signature = bridge2_sign_phantom_agent(chain, hash, wallet);
    chain
        .bridge2_cid()
        .send(action, (arg, nonce, sol_validator_set.clone(), vec![signature]), eth_client)
        .await
        .unwrap();
}

lazy_static! {
    static ref NODES_RUNNING: Mutex<bool> = Mutex::new(false);
}
