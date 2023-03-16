// This test spins up tendermint, abci, and hardhat servers in separate threads.
//
// NOTE: This does not compile without all Chameleon Trading rust dependencies.
//
// run_bridge_watcher monitors the old bridge that will be phased out
// run_bridge_watcher2 monitors the current bridge being audited
// Replicator, HyperAbci, *Action, and other unexplained things relate to the L1,
// so please take those as black boxes that work.
//
// The most relevant tests that isolate the bridge being audited are
// bridge2_withdrawal_tests and bridge2_update_validator_tests

use crate::prelude::*;
use crate::{
    abci_state::AbciStateBuilder,
    bridge2::{ValidatorSet, WithdrawalVoucher2},
    bridge_watcher::{run as run_bridge_watcher, DepositEvent},
    bridge_watcher2::run as run_bridge_watcher2,
    etherscan::TXS,
    hyper_abci::{HyperAbci, ReplicaAbciCmd},
};
use ethers::prelude::k256::ecdsa::SigningKey;
use infra::shell;

async fn setup() -> Recver<ReplicaAbciCmd> {
    assert!(!*NODES_RUNNING.lock());
    *NODES_RUNNING.lock() = true;
    utils::spawn_and_reset_tendermint_node(None, None);
    let (sender, recver) = channel();
    let hyper_abci = HyperAbci::new(AbciStateBuilder::New { chain: Chain::Local }, sender, false);
    std::thread::spawn(move || hyper_abci.run_server_blocking(None));
    spawn_hardhat_node().await;
    lu::async_sleep(Duration(1.)).await;
    recver
}

#[tokio::test]
async fn node_test() {
    if shell("which tendermint".to_string()).output().is_err() {
        // TODO do additional checks here to make sure we're in CI?
        return;
    }
    let recver = setup().await;
    EthClient::skip_api_validation();

    let chain = Chain::Local;
    let owner_eth_client = chain.eth_client(Nickname::Owner).await;
    let not_owner_eth_client = chain.eth_client(Nickname::MarketMaker0).await;
    owner_eth_client.send_eth(not_owner_eth_client.address(), 1.).await.unwrap();

    let owner_wallet = Nickname::Owner.wallet(chain);

    let replicator = Arc::new(Replicator::new(AbciStateBuilder::New { chain }.build(), recver, None).await);
    let tx_batcher = Arc::new(TxBatcher::new("127.0.0.1").await);
    let initial_account_value = account_value(&replicator, User::new(owner_eth_client.address()));

    let user_wallet = tu::wallet(1);
    let agent_wallet = tu::wallet(4);
    let req = utils::approve_agent_action(&user_wallet, &agent_wallet).unwrap();

    tx_batcher.send_signed_action(req).await.unwrap();

    tx_batcher
        .send_signed_action(
            SignedAction::new(
                Box::new(RegisterAssetAction { coin: "ETH".to_string(), sz_decimals: 1, oracle_px: 1000. }),
                &owner_wallet,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    tx_batcher
        .send_signed_action(
            SignedAction::new(
                Box::new(RegisterAssetAction { coin: "BTC".to_string(), sz_decimals: 1, oracle_px: 1000. }),
                &owner_wallet,
            )
            .unwrap(),
        )
        .await
        .unwrap();

    let action = tu::o(1, Side::Bid, 123400000., 1.).into_action();
    let req = SignedAction::new(action, &agent_wallet).unwrap();
    let resp = tx_batcher.send_signed_action(req).await.unwrap();
    let FResult::Ok(SignedActionSuccess::Order(OrderResponse { statuses })) = resp else {
        unreachable!("{resp:?}")
    };

    assert_eq!(statuses.len(), 1);
    assert!(
        u::serde_eq(&statuses[0], &OrderStatus::Error("Insufficient margin to place order.".to_string())),
        "{statuses:?}"
    );

    let cancel_action = CancelAction { cancels: vec![Cancel { asset: 0, oid: 123 }] };
    let req = SignedAction::new(Box::new(cancel_action), &agent_wallet).unwrap();
    let resp = tx_batcher.send_signed_action(req).await.unwrap();
    let FResult::Ok(SignedActionSuccess::Cancel(CancelResponse {statuses})) = resp else {
        unreachable!("{resp:?}")
    };

    assert_eq!(statuses.len(), 1);
    assert!(
        u::serde_eq(
            &statuses[0],
            &CancelStatus::Error("Order was never placed, already canceled, or filled.".to_string())
        ),
        "{statuses:?}"
    );

    run_bridge_watcher(chain, Arc::clone(&replicator), Arc::clone(&tx_batcher)).await;

    let amount = 10.0;
    let owner_usdc_amount = (5. * amount).with_decimals(USDC_ERC20_DECIMALS);
    let not_owner_eth_client_usdc_amount = (3. * amount).with_decimals(USDC_ERC20_DECIMALS);

    chain
        .usdc_cid()
        .send("mint", owner_usdc_amount + not_owner_eth_client_usdc_amount, &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send("transfer", (not_owner_eth_client.address(), not_owner_eth_client_usdc_amount), &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send("approve", (chain.bridge_cid().address(owner_eth_client.chain()), owner_usdc_amount), &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send(
            "approve",
            (chain.bridge_cid().address(owner_eth_client.chain()), not_owner_eth_client_usdc_amount),
            &not_owner_eth_client,
        )
        .await
        .unwrap();

    let initial_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(initial_owner_usdc_balance, owner_usdc_amount);
    let initial_not_owner_eth_client_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", not_owner_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(initial_not_owner_eth_client_usdc_balance, not_owner_eth_client_usdc_amount);

    let tx_receipt =
        chain.bridge_cid().send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.clone().transaction_hash;
    TXS.lock().insert(tx_hash);

    let tx_receipt =
        chain.bridge_cid().send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.clone().transaction_hash;
    TXS.lock().insert(tx_hash);

    lu::async_sleep(Duration(3.)).await;

    let deposit_events: Vec<DepositEvent> = owner_eth_client.parse_events(chain.bridge_cid(), tx_receipt);
    let DepositEvent { user, usdc, .. } = *deposit_events.first().unwrap();
    assert_eq!(usdc.to_string(), "10000000");
    assert_eq!(user, owner_eth_client.address().raw());
    let final_account_value = account_value(&replicator, User::new(owner_eth_client.address()));

    warn!("should have deposited" => initial_account_value, final_account_value, owner_eth_client.address());
    assert_eq!(final_account_value - initial_account_value, 2. * amount);
    let initial_account_value = account_value(&replicator, User::new(owner_eth_client.address()));

    let nonce = 1;
    let withdraw_amount = 10.0.with_decimals(USDC_ERC20_DECIMALS);
    let withdraw_action = WithdrawAction { usd: withdraw_amount, nonce };

    let signing_key = SigningKey::from_bytes(&owner_eth_client.key().to_fixed_bytes()).unwrap();
    let owner_wallet = Wallet::from(signing_key);
    let agent_wallet = tu::wallet(5);
    let req = utils::approve_agent_action(&owner_wallet, &agent_wallet).unwrap();
    tx_batcher.send_signed_action(req).await.unwrap();

    let req = SignedAction::new(Box::new(withdraw_action), &agent_wallet).unwrap();
    tx_batcher.send_signed_action(req).await.unwrap();

    let user = User::new(owner_eth_client.address());
    let final_account_value = account_value(&replicator, user);
    assert_eq!(initial_account_value - final_account_value, amount);

    let mut pending_withdrawals = replicator.bridge_cloned().pending_withdrawals(user).unwrap().clone();
    assert!(pending_withdrawals.len() == 1);
    let withdrawal_voucher = pending_withdrawals.pop().unwrap();
    warn!("pending withdrawal" => withdrawal_voucher);

    let mut incorrect_amount_voucher = withdrawal_voucher.clone();
    incorrect_amount_voucher.action.usd = 1000.0.with_decimals(USDC_ERC20_DECIMALS);
    let res = claim_withdrawal_on_bridge(chain, incorrect_amount_voucher, &owner_eth_client).await;
    assert!(res.err().unwrap().to_string().contains("Withdrawal not signed by Hyperliquid."));

    let tx_receipt = claim_withdrawal_on_bridge(chain, withdrawal_voucher.clone(), &owner_eth_client).await.unwrap();
    let tx_hash = tx_receipt.transaction_hash;
    TXS.lock().insert(tx_hash);

    let res = claim_withdrawal_on_bridge(chain, withdrawal_voucher, &owner_eth_client).await;
    assert!(res.err().unwrap().to_string().contains("Already withdrawn."));

    lu::async_sleep(Duration(2.)).await;

    let pending_withdrawals = replicator.bridge_cloned().pending_withdrawals(user).unwrap().clone();
    warn!("should have no pending withdrawals" => user, pending_withdrawals);

    let is_locked: bool = chain.bridge_cid().call("isLocked", (), &owner_eth_client).await.unwrap();
    assert!(!is_locked);
    let res = chain.bridge_cid().send("setIsLocked", true, &not_owner_eth_client).await;
    tu::assert_err(res, "Ownable: caller is not the owner");
    chain.bridge_cid().send("setIsLocked", true, &owner_eth_client).await.unwrap();
    let is_locked: bool = chain.bridge_cid().call("isLocked", (), &owner_eth_client).await.unwrap();
    assert!(is_locked);

    let nonce = 2;
    let withdraw_action = WithdrawAction { usd: withdraw_amount, nonce };
    let req = SignedAction::new(Box::new(withdraw_action), &agent_wallet).unwrap();
    tx_batcher.send_signed_action(req).await.unwrap();
    let mut pending_withdrawals = replicator.bridge_cloned().pending_withdrawals(user).unwrap().clone();
    let withdrawal_voucher = pending_withdrawals.pop().unwrap();
    let res = claim_withdrawal_on_bridge(chain, withdrawal_voucher, &owner_eth_client).await;
    tu::assert_err(res, "Cannot withdraw/deposit from/to locked bridge");

    let res = chain.bridge_cid().send("withdrawAllUsdcToOwner", (), &not_owner_eth_client).await;
    tu::assert_err(res, "Ownable: caller is not the owner");
    let bridge_usdc_balance: u64 = chain
        .usdc_cid()
        .call("balanceOf", chain.bridge_cid().address(EthChain::Localhost), &owner_eth_client)
        .await
        .unwrap();
    let old_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    chain.bridge_cid().send("withdrawAllUsdcToOwner", (), &owner_eth_client).await.unwrap();
    let new_owner_usdc_balance: u64 =
        chain.usdc_cid().call("balanceOf", owner_eth_client.address(), &owner_eth_client).await.unwrap();
    assert_eq!(new_owner_usdc_balance, old_owner_usdc_balance + bridge_usdc_balance);

    assert!(pending_withdrawals.is_empty());

    chain.bridge_cid().send("setIsLocked", false, &owner_eth_client).await.unwrap();
    chain.bridge_cid().send("setWhitelistOnly", true, &owner_eth_client).await.unwrap();
    let res =
        chain.bridge_cid().send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &not_owner_eth_client).await;
    tu::assert_err(res, "Sender is not whitelisted");
    chain
        .bridge_cid()
        .send("setUsersWhitelistState", (vec![not_owner_eth_client.address().raw()], true), &owner_eth_client)
        .await
        .unwrap();
    chain.bridge_cid().send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &not_owner_eth_client).await.unwrap();

    chain
        .bridge_cid()
        .send("setMaxDepositPerPeriod", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client)
        .await
        .unwrap();
    let seconds_per_deposit_period: u64 = 24 * 60 * 60;
    chain.bridge_cid().send("setSecondsPerDepositPeriod", seconds_per_deposit_period, &owner_eth_client).await.unwrap();
    let receipt = chain
        .bridge_cid()
        .send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &not_owner_eth_client)
        .await
        .unwrap();
    let timestamp = not_owner_eth_client.receipt_to_block(&receipt).await.unwrap().timestamp.without_decimals(0);

    let amount_deposited_this_period: u64 = chain
        .bridge_cid()
        .call(
            "amountDepositedPerPeriod",
            (timestamp as u64 / seconds_per_deposit_period, not_owner_eth_client.address().raw()),
            &not_owner_eth_client,
        )
        .await
        .unwrap();
    assert_eq!(amount_deposited_this_period, amount.with_decimals(USDC_ERC20_DECIMALS));
    let res = chain
        .bridge_cid()
        .send("deposit", (0.5 * amount).with_decimals(USDC_ERC20_DECIMALS), &not_owner_eth_client)
        .await;
    tu::assert_err(res, "deposit amount exceeds the maximum for this period");

    TXS.lock().clear();

    let start_epoch = bridge2_update_validator_tests().await;
    bridge2_withdrawal_tests(start_epoch, None).await;

    assert!(replicator.bridge2_cloned().is_some());
    run_bridge_watcher2(chain, Arc::clone(&replicator), Arc::clone(&tx_batcher)).await;
    assert_eq!(replicator.validator_user(main_validator()).unwrap(), main_validator_user());

    let action = Box::new(OwnerMintTokenForAction { amount: 99, user });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    tx_batcher.send_signed_action(signed_action).await.unwrap();

    let action = Box::new(TokenDelegateAction { validator: main_validator(), amount: 99 });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    tx_batcher.send_signed_action(signed_action).await.unwrap();

    let tx_receipt = chain
        .bridge2_cid()
        .send("deposit", amount.with_decimals(USDC_ERC20_DECIMALS), &owner_eth_client)
        .await
        .unwrap();
    let tx_hash = tx_receipt.clone().transaction_hash;
    TXS.lock().insert(tx_hash);

    lu::async_sleep(Duration(3.)).await;
    let deposit_events: Vec<DepositEvent> = owner_eth_client.parse_events(chain.bridge2_cid(), tx_receipt);
    let DepositEvent { usdc, .. } = *deposit_events.first().unwrap();
    assert_eq!(usdc.to_string(), "10000000");

    lu::async_sleep(Duration(3.)).await;
    let claimable_withdrawals = replicator.claimable_withdrawals(user);
    assert!(!claimable_withdrawals.is_empty());
    let withdrawal_voucher = claimable_withdrawals.first().unwrap();
    warn!("withdrawing from bridge2" => withdrawal_voucher);

    let res = tu::bridge2_withdrawal(&chain, &not_owner_eth_client, withdrawal_voucher.clone()).await;
    tu::assert_err(res, "Validator signature does not match");
    tu::bridge2_withdrawal(&chain, &owner_eth_client, withdrawal_voucher.clone()).await.unwrap();
    let res = tu::bridge2_withdrawal(&chain, &owner_eth_client, withdrawal_voucher.clone()).await;
    tu::assert_err(res, "Already withdrawn");
}

async fn spawn_hardhat_node() {
    std::thread::spawn(|| {
        shell("(cd ~/cham/code/hyperliquid && npx hardhat node) > /tmp/hardhat_out 2>&1".to_string()).wait_check()
    });
    lu::async_sleep(Duration(1.)).await;
    shell("(cd ~/cham/code/hyperliquid && npx hardhat run deploy/contracts.js --network localhost) > /tmp/hardhat_deploy_out 2>&1".to_string()).wait_check();
}

fn account_value(replicator: &Replicator, user: User) -> f64 {
    replicator.web_data(Some(user)).user_state.margin_summary.account_value.0
}

async fn claim_withdrawal_on_bridge(
    chain: Chain,
    withdrawal_voucher: WithdrawalVoucher,
    client: &EthClient,
) -> infra::Result<Receipt> {
    let WithdrawalVoucher { signature, action: WithdrawAction { usd, nonce }, .. } = withdrawal_voucher;
    chain.bridge_cid().send("withdraw", (signature, usd, nonce), client).await
}

async fn bridge2_update_validator_tests() -> Epoch {
    let chain = Chain::Local;
    let eth_chain = chain.eth_chain();

    let eth_client = chain.eth_client(Nickname::Owner).await;
    let signing_key = SigningKey::from_bytes(&eth_client.key().to_fixed_bytes()).unwrap();

    let wallet0 = Wallet::from(signing_key);
    let wallet1 = tu::wallet(1);
    let wallet2 = tu::wallet(2);
    let wallet3 = tu::wallet(3);

    let user0 = wallet0.address().into();
    let user1 = wallet1.address().into();
    let user2 = wallet2.address().into();
    let user3 = wallet3.address().into();

    warn!("running bridge2_update_validator_tests" => user0, user1, user2, user3);

    let cur_validator_set = ValidatorSet { epoch: 0, validators: vec![user0], powers: vec![100] };
    let new_validator_set = ValidatorSet { epoch: 1, validators: vec![user1, user2], powers: vec![50, 50] };
    utils::update_validator_set(&eth_client, chain, &cur_validator_set, &new_validator_set, &[wallet0]).await.unwrap();

    let cur_validator_set = new_validator_set;

    let new_validator_set = ValidatorSet { epoch: 2, validators: vec![user1, user2, user3], powers: vec![50, 25, 25] };
    utils::update_validator_set(
        &eth_client,
        chain,
        &cur_validator_set,
        &new_validator_set,
        &[wallet1.clone(), wallet2.clone()],
    )
    .await
    .unwrap();

    let amount = 10.0;
    let usd = amount.with_decimals(USDC_ERC20_DECIMALS);
    let nonce = 0;
    let hash = utils::keccak((user0.raw(), usd, nonce));
    let signatures = vec![utils::phantom_agent(hash).sign_typed_data(chain.eth_chain(), &wallet1).unwrap()];
    let withdrawal_voucher_no_quorum = WithdrawalVoucher2 {
        usd,
        nonce,
        cur_validator_set: new_validator_set.clone(),
        signers: vec![user1],
        signatures,
    };

    let res = tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher_no_quorum).await;
    tu::assert_err(res, "Submitted validator set signatures do not have enough power");

    chain.usdc_cid().send("approve", (chain.bridge2_cid().address(eth_chain), u64::MAX), &eth_client).await.unwrap();
    chain.bridge2_cid().send("deposit", usd, &eth_client).await.unwrap();

    let mut signatures = Vec::new();
    for wallet in [&wallet1, &wallet2, &wallet3] {
        signatures.push(utils::phantom_agent(hash).sign_typed_data(eth_chain, wallet).unwrap());
    }
    let cur_validator_set = new_validator_set.clone();
    let withdrawal_voucher = WithdrawalVoucher2 {
        usd,
        nonce,
        cur_validator_set: cur_validator_set.clone(),
        signers: cur_validator_set.validators.clone(),
        signatures,
    };
    tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher).await.unwrap();

    let new_validator_set = ValidatorSet { epoch: 3, validators: vec![user1, user2, user3], powers: vec![50, 25, 25] };
    let sol_new_validator_set = new_validator_set.into_sol();
    let sol_cur_validator_set = sol_new_validator_set.clone();

    let sol_new_validator_set_hash = sol_new_validator_set.hash();
    let mut signatures = Vec::new();
    for validator in [&wallet1, &wallet2, &wallet3] {
        signatures.push(
            utils::phantom_agent(sol_new_validator_set_hash).sign_typed_data(chain.eth_chain(), validator).unwrap(),
        );
    }
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (
                sol_new_validator_set.clone(),
                sol_cur_validator_set.clone(),
                cur_validator_set.signers(),
                signatures.clone(),
            ),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Supplied current validators and powers do not match checkpoint");

    let cur_validator_set = ValidatorSet { epoch: 2, validators: vec![user1, user2, user3], powers: vec![50, 25, 25] };
    let cur_signers = cur_validator_set.signers();
    let sol_cur_validator_set = cur_validator_set.into_sol();
    let sol_new_validator_set = sol_cur_validator_set.clone();
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (
                sol_new_validator_set,
                sol_cur_validator_set.clone(),
                sol_cur_validator_set.validators.clone(),
                signatures.clone(),
            ),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "New validator set epoch must be greater than the current epoch");

    let new_validator_set = ValidatorSet { epoch: 3, validators: vec![user1, user2, user3], powers: vec![50, 25, 25] };
    let sol_new_validator_set = new_validator_set.into_sol();
    let mut wrong_signatures = Vec::new();
    for validator in &[&wallet1, &wallet3, &wallet3] {
        wrong_signatures.push(
            utils::phantom_agent(sol_new_validator_set_hash).sign_typed_data(chain.eth_chain(), validator).unwrap(),
        );
    }
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (
                sol_new_validator_set.clone(),
                sol_cur_validator_set.clone(),
                sol_cur_validator_set.validators.clone(),
                wrong_signatures,
            ),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Validator signature does not match");

    let no_quorum_signatures =
        vec![utils::phantom_agent(sol_new_validator_set_hash).sign_typed_data(chain.eth_chain(), &wallet1).unwrap()];
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (sol_new_validator_set, sol_cur_validator_set.clone(), vec![user1.raw()], no_quorum_signatures),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Submitted validator set signatures do not have enough power");

    let new_validator_set = ValidatorSet { epoch: 3, validators: vec![user1, user2], powers: vec![50, 15] };
    let sol_new_validator_set = new_validator_set.clone().into_sol();
    let res = chain
        .bridge2_cid()
        .send(
            "updateValidatorSet",
            (sol_new_validator_set, sol_cur_validator_set.clone(), cur_signers, signatures),
            &eth_client,
        )
        .await;
    tu::assert_err(res, "Submitted validator powers is less than minTotalValidatorPower");

    let new_validator_wallets = utils::wallet_range(100);
    let new_validators_users = new_validator_wallets.iter().map(|wallet| wallet.address().into()).collect();
    let powers = vec![1_u64; 100];

    let new_validator_set = ValidatorSet { epoch: 3, validators: new_validators_users, powers: powers.clone() };
    let cur_validator_set = ValidatorSet { epoch: 2, validators: vec![user1, user2, user3], powers: vec![50, 25, 25] };
    let wallets = [wallet1.clone(), wallet2.clone(), wallet3.clone()];
    utils::update_validator_set(&eth_client, chain, &cur_validator_set, &new_validator_set, &wallets).await.unwrap();

    let end_epoch = 4;
    let cur_validator_set = new_validator_set;
    let new_validator_set = ValidatorSet { epoch: end_epoch, validators: vec![user0], powers: vec![100] };
    utils::update_validator_set(
        &eth_client,
        chain,
        &cur_validator_set,
        &new_validator_set,
        new_validator_wallets.as_slice(),
    )
    .await
    .unwrap();

    end_epoch
}

async fn bridge2_withdrawal_tests(start_epoch: Epoch, end_epoch: Option<Epoch>) {
    let chain = Chain::Local;
    let eth_client = chain.eth_client(Nickname::Owner).await;
    let signing_key = SigningKey::from_bytes(&eth_client.key().to_fixed_bytes()).unwrap();
    let wallet0 = Wallet::from(signing_key);
    let user0: User = wallet0.address().into();

    let powers = vec![25, 1, 10, 10, 10, 6, 3, 2, 1, 88];
    let wallets = utils::wallet_range(10);
    let tot_power: u64 = powers.iter().sum();

    let cur_validator_set = ValidatorSet { epoch: start_epoch, validators: vec![user0], powers: vec![100] };
    let new_epoch = start_epoch + 1;
    let validators: Vec<_> = wallets.iter().map(|wallet| wallet.address().into()).collect();
    let new_validator_set = ValidatorSet { epoch: new_epoch, validators: validators.clone(), powers: powers.clone() };
    utils::update_validator_set(&eth_client, chain, &cur_validator_set, &new_validator_set, &[wallet0]).await.unwrap();

    let quorum_threshold = (2. * tot_power as f64) / 3.;
    let mut nonce = 0;
    let usd = 1.0.with_decimals(USDC_ERC20_DECIMALS);
    chain.bridge2_cid().send("deposit", 30 * usd, &eth_client).await.unwrap();

    let cur_validator_set = ValidatorSet { epoch: new_epoch, validators, powers: powers.clone() };
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
        let hash = utils::keccak((user0.raw(), usd, nonce));

        for &i in &inds {
            let wallet = &wallets[i];
            let power = powers[i];
            signatures.push(utils::phantom_agent(hash).sign_typed_data(chain.eth_chain(), wallet).unwrap());
            signers.push(wallet.address().into());
            tot_sample_power += power;
            sample_powers.push(power);
        }

        let quorum_reached = tot_sample_power as f64 >= quorum_threshold;
        warn!("withdrawal fuzz test working on" => inds, quorum_reached);

        let withdrawal_voucher =
            WithdrawalVoucher2 { usd, nonce, signers, cur_validator_set: cur_validator_set.clone(), signatures };
        nonce += 1;

        let res = tu::bridge2_withdrawal(&chain, &eth_client, withdrawal_voucher).await;
        assert_eq!(res.is_ok(), quorum_reached, "inds={inds:?} res={res:?}");
    }

    // return to state that the node integration test can use
    let epoch = match end_epoch {
        Some(epoch) => epoch,
        None => InfraTime::wall_clock_now().to_unix_millis() / 1_000_000,
    };
    let new_validator_set = ValidatorSet { epoch, validators: vec![main_validator_user()], powers: vec![100] };
    utils::update_validator_set(&eth_client, chain, &cur_validator_set, &new_validator_set, wallets.as_slice())
        .await
        .unwrap();
}

// TODO do not hardcode
fn main_validator_user() -> User {
    "0x7662db3a3c4243ad55b7cf230357b1a8af0e15fc".parse().unwrap()
}

fn main_validator() -> H256 {
    let signing_key = utils::ed25519_signing_key("golden_inputs/priv_validator_key.json");
    signing_key.verification_key().to_bytes().into()
}

lazy_static! {
    static ref NODES_RUNNING: Mutex<bool> = Mutex::new(false);
}
