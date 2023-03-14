// This test spins up tendermint, abci, and hardhat servers in separate threads.
//
// NOTE: This does not compile without all Chameleon Trading rust dependencies.
// run_bridge_watcher monitors the old bridge that will be phased out
// run_bridge_watcher2 monitors the current bridge being audited
// Replicator, HyperAbci, *Action, and other unexplained things relate to the L1,
// so please take those as black boxes that work.

use crate::prelude::*;
use crate::{
    abci_state::AbciStateBuilder,
    bridge2::ValidatorSet,
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

    run_bridge_watcher(Chain::Local, Arc::clone(&replicator), Arc::clone(&tx_batcher)).await;

    let amount = 10.0;
    let owner_usdc_amount = (2. * amount).with_decimals(USDC_ERC20_DECIMALS);
    let not_owner_eth_client_usdc_amount = (3. * amount).with_decimals(USDC_ERC20_DECIMALS);

    chain
        .usdc_cid()
        .send("mint", owner_usdc_amount + not_owner_eth_client_usdc_amount, &owner_eth_client)
        .await
        .unwrap();
    chain
        .usdc_cid()
        .send(
            "transfer",
            (not_owner_eth_client.address(), (3. * amount).with_decimals(USDC_ERC20_DECIMALS)),
            &owner_eth_client,
        )
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

    assert!(replicator.bridge2_cloned().is_some());

    run_bridge_watcher2(Chain::Local, Arc::clone(&replicator), Arc::clone(&tx_batcher)).await;

    let cur_validator_set = ValidatorSet { epoch: 0, validators: vec![user], powers: vec![100] };
    let signing_key = utils::ed25519_signing_key("golden_inputs/priv_validator_key.json");
    let owner_validator_address = signing_key.verification_key().to_bytes().into();
    let validator_user = replicator.validator_user(owner_validator_address).unwrap();

    let sol_cur_validator_set = tu::SolValidatorSet::from_validator_set(cur_validator_set.clone());
    let validator_set_checkpoint: H256 =
        chain.bridge2_cid().call("validatorSetCheckpoint", (), &owner_eth_client).await.unwrap();
    assert_eq!(sol_cur_validator_set.hash(), validator_set_checkpoint);

    let cur_epoch = InfraTime::wall_clock_now().to_unix_millis() / 1_000_000;
    let new_validator_set = ValidatorSet { epoch: cur_epoch, validators: vec![validator_user], powers: vec![100] };
    let sol_new_validator_set = tu::SolValidatorSet::from_validator_set(new_validator_set.clone());

    let signature =
        utils::phantom_agent(sol_new_validator_set.hash()).sign_typed_data(chain.eth_chain(), &owner_wallet).unwrap();
    chain
        .bridge2_cid()
        .send("updateValidatorSet", (sol_new_validator_set, sol_cur_validator_set, vec![signature]), &owner_eth_client)
        .await
        .unwrap();

    let action = Box::new(OwnerMintTokenForAction { amount: 99, user });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    tx_batcher.send_signed_action(signed_action).await.unwrap();

    let action = Box::new(TokenDelegateAction { validator: owner_validator_address, amount: 99 });
    let signed_action = SignedAction::new(action, &owner_wallet).unwrap();
    tx_batcher.send_signed_action(signed_action).await.unwrap();

    chain
        .usdc_cid()
        .send(
            "approve",
            (chain.bridge2_cid().address(owner_eth_client.chain()), amount.with_decimals(USDC_ERC20_DECIMALS)),
            &owner_eth_client,
        )
        .await
        .unwrap();

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
    tu::bridge2_withdrawal(&chain, owner_eth_client, claimable_withdrawals.first().unwrap()).await.unwrap();
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

lazy_static! {
    static ref NODES_RUNNING: Mutex<bool> = Mutex::new(false);
}
