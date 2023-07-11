// This task is run asynchronously by each node process.
// The task listens to events emitted by the Arbitrum contract and sends relevant L1 signatures and
// Arbitrum finalization transactions.

use crate::prelude::*;
use crate::{
    action::{
        sign_validator_set_update::SignValidatorSetUpdateAction,
        vote_eth_claimed_withdrawal::VoteEthRequestedWithdrawalAction, vote_eth_deposit::VoteEthDepositAction,
        vote_eth_finalized_validator_set_update::VoteEthFinalizedValidatorSetUpdateAction,
        vote_eth_finalized_withdrawal::VoteEthFinalizedWithdrawalAction,
        vote_eth_validator_set_update::VoteEthValidatorSetUpdateAction, ValidatorSignWithdrawalAction,
    },
    bridge2::{
        finalize_validator_set_update, Bridge2, PendingValidatorSetUpdate, SolValidatorSet, SolValidatorSetUpdate,
        UserAndNonce, Withdrawal,
    },
    bridge_watcher::query_tx_receipt,
    etherscan_tx_tracker::EtherscanTxTracker,
    staking::Staking,
};

#[derive(Debug)]
pub(crate) enum Event {
    Deposit(DepositEvent),
    RequestedWithdrawal(RequestedWithdrawalEvent),
    FinalizedWithdrawal(FinalizedWithdrawalEvent),
    RequestedValidatorSetUpdate(RequestedValidatorSetUpdateEvent),
    FinalizedValidatorSetUpdate(FinalizedValidatorSetUpdateEvent),
}

#[derive(Clone, Copy, EnumIter)]
enum EventType {
    Deposit,
    RequestedWithdrawal,
    FinalizedWithdrawal,
    RequestedValidatorSetUpdate,
    FinalizedValidatorSetUpdate,
}

#[derive(Debug, EthAbiType)]
pub(crate) struct DepositEvent {
    pub(crate) user: H160,
    pub(crate) usdc: u64,
}

#[derive(Debug, EthAbiType)]
pub(crate) struct RequestedWithdrawalEvent {
    pub(crate) user: H160,
    pub(crate) usdc: u64,
    pub(crate) nonce: u64,
    pub(crate) message: H256,
    pub(crate) requested_time: u64,
    pub(crate) block_number: u64,
}

#[derive(Debug, EthAbiType)]
pub(crate) struct FinalizedWithdrawalEvent {
    pub(crate) user: H160,
    pub(crate) usdc: u64,
    pub(crate) nonce: u64,
    pub(crate) message: H256,
}

#[derive(Debug, EthAbiType)]
pub(crate) struct RequestedValidatorSetUpdateEvent {
    pub(crate) epoch: Epoch,
    pub(crate) hot_validator_set_hash: H256,
    pub(crate) cold_validator_set_hash: H256,
    pub(crate) update_time: u64,
    pub(crate) block_number: u64,
}

#[derive(Debug, EthAbiType)]
pub(crate) struct FinalizedValidatorSetUpdateEvent {
    pub(crate) epoch: Epoch,
    pub(crate) hot_validator_set_hash: H256,
    pub(crate) cold_validator_set_hash: H256,
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
struct ValidatorSetUpdateArgs {
    sol_new_validator_set: SolValidatorSetUpdate,
    sol_cur_validator_set: SolValidatorSet,
    signers: Vec<H160>,
    signatures: Vec<Signature>,
}

pub(crate) async fn spawn(replicator: Arc<Replicator>, tx_batcher: Arc<TxBatcher>, should_finalize: bool) {
    utils::tokio_spawn_forever("BridgeWatcher2", async move {
        let chain = replicator.lock(|e| e.chain(), "bw2_chain");
        let client = chain.eth_client(Nickname::Owner).await;

        let priv_validator_key_file = if_test!(
            "golden_inputs/priv_validator_key.json".to_string(),
            format!("{}/code/hyperliquid/data/tendermint/priv_validator_key.json", C.cham_dir)
        );
        let signing_key = utils::ed25519_signing_key(&priv_validator_key_file);
        let validator: H256 = signing_key.verification_key().to_bytes().into();
        let validator_wallet = utils::wallet(validator);
        let mut l1_actions_time_stream = lu::timer_stream(Duration(if_test!(0.5, 2.)), None);
        let mut eth_actions_time_stream = lu::timer_stream(Duration(if_test!(0.5, 30.)), None);

        let dispute_period_millis = dispute_period_millis(&client, chain).await;
        let block_duration_millis = chain.bridge2_cid().call("blockDurationMillis", (), &client).await.unwrap();

        let eth_chain = chain.eth_chain();
        let bridge_address = chain.bridge2_cid().address(eth_chain);
        let etherscan_tx_tracker = EtherscanTxTracker::new(chain, bridge_address);
        loop {
            let validator_active = replicator.lock(|e| e.staking().validator_active(validator), "bw2_validator_active");
            if validator_active {
                break;
            }
            error!("BridgeWatcher2: Owner is not a registered validator." => validator);
            lu::async_sleep(Duration(5.)).await;
        }

        loop {
            tokio::select! {
                Some(_) = l1_actions_time_stream.next() => {
                    let txs = etherscan_tx_tracker.lock().txs(eth_chain, bridge_address).clone();
                    let bridge2 = replicator.lock(|e| e.bridge2().clone(), "bw2_bridge2");
                    if let Err(err) =
                        register_eth_events_on_l1(chain, &client, &bridge2, &tx_batcher, &validator_wallet, &txs).await
                    {
                        // NOSHIP investigate why this errors but not in bridge_watcher
                        error!("Error running register_eth_events_on_l1: {err}");
                    }

                    if let Err(err) = sign_l1_actions(&bridge2, &tx_batcher, &validator_wallet, chain, validator).await {
                        error!("Error running sign_l1_actions: {err}");
                    }
                }

                Some(_) = eth_actions_time_stream.next() => {
                    let pending_validator_set_update: PendingValidatorSetUpdate =
                        chain.bridge2_cid().call("pendingValidatorSetUpdate", (), &client).await.unwrap();
                    let (bridge2, staking) = replicator.lock(|e| (e.bridge2().clone(), e.staking().clone()), "bw2_bridge2_and_staking");

                    if let Err(err) =
                        maybe_update_validator_set(&bridge2, &staking, &client, chain, pending_validator_set_update.clone()).await
                    {
                        error!("Error running maybe_update_validator_set: {err}");
                    }

                    if should_finalize {
                        if let Err(err) = maybe_finalize_validator_set_update(&client, chain, pending_validator_set_update, dispute_period_millis, block_duration_millis).await {
                            error!("Error running maybe_finalize_validator_set_update: {err}");
                        }

                        if let Err(err) = batch_finalize_withdrawals(&bridge2, &client, chain, dispute_period_millis, block_duration_millis).await {
                            error!("Error running batch_finalize_withdrawals: {err}");
                        }
                    }
                }
            }
        }
    });
}

async fn register_eth_events_on_l1(
    chain: Chain,
    client: &EthClient,
    bridge2: &Bridge2,
    tx_batcher: &TxBatcher,
    owner_wallet: &Wallet,
    txs: &Set<H256>,
) -> infra::Result<u64> {
    let events = etherscan_events(chain, client, txs).await?;

    let mut last_seen_block = 0;
    let processed_deposits = bridge2.processed_deposits().clone();
    for (eth_id, (event, tx_receipt)) in events {
        let cur_block = tx_receipt.block_number.unwrap().as_u64();
        last_seen_block = last_seen_block.max(cur_block);
        if !processed_deposits.contains(&eth_id) {
            let action: Box<dyn ActionTrait> = match event {
                Event::Deposit(DepositEvent { user, usdc, .. }) => Box::new(VoteEthDepositAction {
                    user: user.into(),
                    usd: usdc,
                    eth_id,
                    eth_tx_hash: tx_receipt.transaction_hash,
                }),
                Event::RequestedWithdrawal(RequestedWithdrawalEvent {
                    user,
                    nonce,
                    requested_time,
                    usdc,
                    block_number,
                    ..
                }) => Box::new(VoteEthRequestedWithdrawalAction {
                    user: user.into(),
                    usd: usdc,
                    nonce,
                    requested_time: Time::from_unix_millis(requested_time * 1000).unwrap(),
                    block_number,
                }),
                Event::FinalizedWithdrawal(FinalizedWithdrawalEvent { user, nonce, usdc, .. }) => {
                    Box::new(VoteEthFinalizedWithdrawalAction { user: user.into(), nonce, usd: usdc })
                }
                Event::RequestedValidatorSetUpdate(RequestedValidatorSetUpdateEvent {
                    epoch,
                    hot_validator_set_hash,
                    cold_validator_set_hash,
                    update_time,
                    block_number,
                }) => {
                    let validator_set_hash = utils::keccak((hot_validator_set_hash, cold_validator_set_hash));
                    Box::new(VoteEthValidatorSetUpdateAction {
                        epoch,
                        update_time: Time::from_unix_millis(update_time * 1000).unwrap(),
                        validator_set_hash,
                        block_number,
                    })
                }
                Event::FinalizedValidatorSetUpdate(FinalizedValidatorSetUpdateEvent {
                    epoch,
                    hot_validator_set_hash,
                    cold_validator_set_hash,
                }) => {
                    let validator_set_hash = utils::keccak((hot_validator_set_hash, cold_validator_set_hash));
                    Box::new(VoteEthFinalizedValidatorSetUpdateAction { epoch, validator_set_hash })
                }
            };
            let signed_action = SignedAction::new(action, owner_wallet)?;
            warn!("register_eth_events_on_l1" => signed_action, owner_wallet);
            tx_batcher.send_signed_action(signed_action).await?;
        } else {
            warn!("Event already processed" => event);
        }
    }

    let _cur_block = client.cur_block_number().await.unwrap();
    Ok(last_seen_block.min(if_test!(0, _cur_block - 10_000)))
}

async fn sign_l1_actions(
    bridge2: &Bridge2,
    tx_batcher: &TxBatcher,
    owner_wallet: &Wallet,
    chain: Chain,
    validator: Validator,
) -> Result<()> {
    let withdrawals_to_sign = bridge2.withdrawal_signatures().without_validator_vote(validator);
    let validator_sets_to_sign = bridge2.validator_set_signatures().without_validator_vote(validator);

    for (&UserAndNonce { user, nonce }, value_to_withdrawal) in withdrawals_to_sign.iter() {
        for &usd in value_to_withdrawal.keys() {
            let hash = utils::keccak((user.raw(), usd, nonce));
            let signature = chain.sign_phantom_agent(hash, owner_wallet);
            let action = Box::new(ValidatorSignWithdrawalAction { user, usd, nonce, signature });
            let req = SignedAction::new(action, owner_wallet).unwrap();
            tx_batcher.send_signed_action(req).await?;
        }
    }

    for (epoch, hash_to_signatures) in validator_sets_to_sign {
        for &validator_set_hash in hash_to_signatures.keys() {
            let signature = chain.sign_phantom_agent(validator_set_hash, owner_wallet);
            let action = Box::new(SignValidatorSetUpdateAction { epoch, validator_set_hash, signature });
            let req = SignedAction::new(action, owner_wallet).unwrap();
            tx_batcher.send_signed_action(req).await?;
        }
    }

    Ok(())
}

// NOSHIP move this into EtherscanTxTracker and don't load the files over and over again
async fn etherscan_events(
    chain: Chain,
    client: &EthClient,
    txs: &Set<H256>,
) -> infra::Result<Map<H256, (Event, Receipt)>> {
    let start = Instant::now();
    let cid = chain.bridge2_cid();
    let mut res = Map::new();
    for event_type in EventType::iter() {
        for tx in txs.clone() {
            let receipt = query_tx_receipt(tx, client).await?;

            let events: Vec<_> = match event_type {
                EventType::Deposit => {
                    client.parse_events(cid, receipt.clone()).into_iter().map(Event::Deposit).collect()
                }
                EventType::RequestedWithdrawal => {
                    client.parse_events(cid, receipt.clone()).into_iter().map(Event::RequestedWithdrawal).collect()
                }
                EventType::FinalizedWithdrawal => {
                    client.parse_events(cid, receipt.clone()).into_iter().map(Event::FinalizedWithdrawal).collect()
                }
                EventType::RequestedValidatorSetUpdate => client
                    .parse_events(cid, receipt.clone())
                    .into_iter()
                    .map(Event::RequestedValidatorSetUpdate)
                    .collect(),
                EventType::FinalizedValidatorSetUpdate => client
                    .parse_events(cid, receipt.clone())
                    .into_iter()
                    .map(Event::FinalizedValidatorSetUpdate)
                    .collect(),
            };
            for (pos, event) in events.into_iter().enumerate() {
                let hash = utils::keccak((pos as u32, tx));
                res.insert(hash, (event, receipt.clone()));
            }
        }
    }
    warn!("parsed all events from etherscan txs" => cid, res.len(), u::profile(start));
    Ok(res)
}

fn validator_set_ready(
    bridge2: &Bridge2,
    staking: &Staking,
    pending_validator_set_update: PendingValidatorSetUpdate,
) -> Option<ValidatorSetUpdateArgs> {
    let validator_sets_ready = bridge2.validator_sets_ready();
    let active_epoch = staking.active_epoch();
    let PendingValidatorSetUpdate { epoch: pending_epoch, .. } = pending_validator_set_update;
    if let Some((&epoch, validator_set_and_signatures)) = validator_sets_ready.iter().rev().next() {
        if epoch <= active_epoch || epoch <= pending_epoch.as_u64() {
            return None;
        }
        let cur_validator_set = staking.validator_set(active_epoch).unwrap();
        let sol_cur_validator_set = SolValidatorSet::from_hot_validator_set(epoch, &cur_validator_set);
        let new_validator_set: Set<_> = validator_set_and_signatures.keys().copied().collect();
        let sol_new_validator_set = SolValidatorSetUpdate::from_validator_set(epoch, &new_validator_set);
        let mut validator_set_and_signatures: Vec<_> = validator_set_and_signatures.iter().collect();
        validator_set_and_signatures.sort_by_key(|(_, x)| Reverse(x.power));
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        for (&validator_profile, validator_signature) in validator_set_and_signatures {
            signers.push(validator_profile.hot_user.raw());
            signatures.push(validator_signature.clone().signature);
        }

        let validator_set_update_args =
            ValidatorSetUpdateArgs { sol_new_validator_set, sol_cur_validator_set, signers, signatures };
        return Some(validator_set_update_args);
    }
    None
}

async fn maybe_update_validator_set(
    bridge2: &Bridge2,
    staking: &Staking,
    client: &EthClient,
    chain: Chain,
    pending_validator_set_update: PendingValidatorSetUpdate,
) -> infra::Result<()> {
    if let Some(new_validator_set_args) = validator_set_ready(bridge2, staking, pending_validator_set_update) {
        warn!("bridge_watcher2: sending new validator set update request" => new_validator_set_args);
        let ValidatorSetUpdateArgs { sol_new_validator_set, sol_cur_validator_set, signers, signatures } =
            new_validator_set_args;
        chain
            .bridge2_cid()
            .send("updateValidatorSet", (sol_new_validator_set, sol_cur_validator_set, signers, signatures), client)
            .await?;
    }
    Ok(())
}

async fn batch_finalize_withdrawals(
    bridge2: &Bridge2,
    client: &EthClient,
    chain: Chain,
    dispute_period_millis: u64,
    block_duration_millis: u64,
) -> infra::Result<()> {
    let withdrawals_to_finalize = bridge2.withdrawals_to_finalize().clone();
    let mut messages = Vec::new();
    let time = InfraTime::wall_clock_now();
    let cur_block_number = client.cur_block_number().await.unwrap();
    for (user_and_nonce, usd_and_time) in withdrawals_to_finalize {
        let Withdrawal { usd, requested_time, block_number } = usd_and_time;
        let enough_time_passed = requested_time.to_unix_millis() + dispute_period_millis > time.to_unix_millis();
        let enough_blocks_passed = (cur_block_number - block_number) * block_duration_millis > dispute_period_millis;
        if enough_time_passed && enough_blocks_passed {
            let UserAndNonce { user, nonce } = user_and_nonce;
            let message = utils::keccak((user.raw(), usd, nonce));
            messages.push(message);
        }
    }

    let batches: Vec<_> = messages.chunks(200).collect();
    for batch in batches {
        let batch = batch.to_vec();
        chain.bridge2_cid().send("batchedFinalizeWithdrawals", batch, client).await?;
    }

    Ok(())
}

async fn maybe_finalize_validator_set_update(
    client: &EthClient,
    chain: Chain,
    pending_validator_set_update: PendingValidatorSetUpdate,
    dispute_period_millis: u64,
    block_duration_millis: u64,
) -> infra::Result<()> {
    let update_time_millis = pending_validator_set_update.update_time.as_u64() * 1000;
    if update_time_millis == 0 {
        warn!("pending validator set update already finalized" => pending_validator_set_update);
        return Ok(());
    }

    let cur_time = InfraTime::wall_clock_now();
    let cur_block_number = client.cur_block_number().await.unwrap();
    let update_block_number = pending_validator_set_update.update_block_number.as_u64();
    let not_enough_time_passed = cur_time.to_unix_millis() < update_time_millis + dispute_period_millis;
    let not_enough_blocks_passed =
        (cur_block_number - update_block_number) * block_duration_millis < dispute_period_millis;
    if not_enough_time_passed || not_enough_blocks_passed {
        warn!("pending validator set update still in dispute period" => pending_validator_set_update);
        return Ok(());
    }
    finalize_validator_set_update(client, chain).await?;
    Ok(())
}

async fn dispute_period_millis(client: &EthClient, chain: Chain) -> u64 {
    let dispute_period_seconds: u64 = chain.bridge2_cid().call("disputePeriodSeconds", (), client).await.unwrap();
    dispute_period_seconds * 1000
}

#[cfg(test)]
mod test {

    use infra::set;

    use super::*;
    use crate::{
        action::sign_validator_set_update::SignValidatorSetUpdateAction,
        bridge2::{make_validator_set_hash, validator_set_hashes, ValidatorProfile, ValidatorSignature},
    };

    #[test]
    fn pending_validator_sets_ready_test() {
        let chain: Chain = Chain::Local;
        let mut staking = Staking::new();
        let mut bridge2 = Bridge2::new();
        let validator = tu::main_validator();
        let validator_wallet = utils::wallet(tu::main_validator());
        let hot_user = tu::main_validator_hot_user();
        let cold_user = tu::main_validator_cold_user();

        staking.maybe_increase_epoch(Time::from_unix_millis(1_000_000).unwrap());
        staking.maybe_increase_epoch(Time::from_unix_millis(2_000_000).unwrap());

        let new_active_epoch = 1;
        let validator_set = set![ValidatorProfile { power: 1, hot_user, cold_user }];
        let hash = make_validator_set_hash(new_active_epoch, validator_set.clone());
        let signature = chain.sign_phantom_agent(hash, &validator_wallet);
        let validator_signatures = map!(validator => ValidatorSignature { signature: signature.clone(), power: 1 });
        let sign_validator_set_update_action = SignValidatorSetUpdateAction {
            epoch: new_active_epoch,
            validator_set_hash: hash,
            signature: signature.clone(),
        };
        bridge2.sign_validator_set_update(chain, hot_user, sign_validator_set_update_action, &staking).unwrap();
        assert_eq!(
            bridge2.validator_set_signatures().validators_and_signatures(new_active_epoch, hash).unwrap(),
            &validator_signatures
        );

        let (hot_validator_set_hash, cold_validator_set_hash) = validator_set_hashes(new_active_epoch, validator_set);
        let pending_validator_set_update = PendingValidatorSetUpdate {
            epoch: U256::zero(),
            total_validator_power: U256::one(),
            update_time: U256::one(),
            update_block_number: U256::zero(),
            hot_validator_set_hash,
            cold_validator_set_hash,
            n_validators: U256::one(),
        };

        let res = validator_set_ready(&bridge2, &staking, pending_validator_set_update).unwrap();
        let powers = vec![U256::one()];
        assert_eq!(
            res,
            ValidatorSetUpdateArgs {
                sol_new_validator_set: SolValidatorSetUpdate {
                    epoch: new_active_epoch.into(),
                    hot_addresses: vec![hot_user.raw()],
                    cold_addresses: vec![cold_user.raw()],
                    powers: powers.clone(),
                },
                sol_cur_validator_set: SolValidatorSet {
                    epoch: new_active_epoch.into(),
                    validators: vec![hot_user.raw()],
                    powers,
                },
                signers: vec![hot_user.raw()],
                signatures: vec![signature]
            }
        );
    }
}
