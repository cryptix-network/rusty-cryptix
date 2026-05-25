use std::{fs, path::Path, str::FromStr, sync::Arc};

use crate::{
    model::stores::{
        ghostdag::GhostdagStoreReader,
        headers::HeaderStoreReader,
        selected_chain::{SelectedChainStore, SelectedChainStoreReader},
        statuses::StatusesStoreReader,
        tips::{TipsStore, TipsStoreReader},
        DB,
    },
    pipeline::virtual_processor::VirtualStateProcessor,
    processes::ghostdag::ordering::SortableBlock,
};
use cryptix_consensus_core::{blockstatus::BlockStatus, ChainPath};
use cryptix_core::{info, warn};
use cryptix_database::prelude::StoreError;
use cryptix_hashes::Hash;
use rocksdb::WriteBatch;
use serde::Deserialize;

use super::storage::ConsensusStorage;

type RepairResult<T> = Result<T, String>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StartupRepairPlan {
    schema_version: u32,
    #[serde(default = "default_true")]
    enabled: bool,
    name: Option<String>,
    #[serde(default)]
    trigger_blocks: Vec<String>,
    require_trigger_block: Option<bool>,
    target_block_hash: Option<String>,
    target_daa: Option<u64>,
    cutoff_daa: Option<u64>,
    #[serde(default = "default_true")]
    mark_removed_disqualified: bool,
    #[serde(default = "default_true")]
    cleanup_removed_block_data: bool,
    #[serde(default)]
    dry_run: bool,
}

fn default_true() -> bool {
    true
}

impl StartupRepairPlan {
    fn require_trigger_block(&self) -> bool {
        self.require_trigger_block.unwrap_or(!self.trigger_blocks.is_empty())
    }

    fn target_daa(&self) -> Option<u64> {
        self.target_daa.or(self.cutoff_daa)
    }

    fn validate(&self) -> RepairResult<()> {
        if self.schema_version != 1 {
            return Err(format!("unsupported startup repair schemaVersion {}", self.schema_version));
        }

        if self.target_block_hash.is_some() == self.target_daa().is_some() {
            return Err("startup repair plan must set exactly one of targetBlockHash or targetDaa/cutoffDaa".to_string());
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
struct RepairTarget {
    index: u64,
    hash: Hash,
    daa: u64,
}

pub(super) fn apply_startup_repair_plan(
    db: &Arc<DB>,
    storage: &Arc<ConsensusStorage>,
    virtual_processor: &Arc<VirtualStateProcessor>,
    path: &Path,
) -> RepairResult<()> {
    let bytes = fs::read(path).map_err(|err| format!("failed reading startup repair plan {}: {}", path.display(), err))?;
    let plan: StartupRepairPlan =
        serde_json::from_slice(&bytes).map_err(|err| format!("failed parsing startup repair plan {}: {}", path.display(), err))?;
    plan.validate()?;

    if !plan.enabled {
        info!("[startup-repair] plan {} is disabled; skipping", plan_label(&plan, path));
        return Ok(());
    }

    if !trigger_matches(storage, &plan)? {
        info!("[startup-repair] plan {} skipped because none of the triggerBlocks exist in local storage", plan_label(&plan, path));
        return Ok(());
    }

    let (current_index, current_tip) = storage
        .selected_chain_store
        .read()
        .get_tip()
        .map_err(|err| format!("startup repair failed reading selected-chain tip: {err}"))?;
    let current_daa = storage
        .headers_store
        .get_daa_score(current_tip)
        .map_err(|err| format!("startup repair failed reading current selected tip DAA for {current_tip}: {err}"))?;
    let target = resolve_target(storage, &plan, current_index)?;

    if target.index == current_index {
        info!(
            "[startup-repair] plan {} no-op: selected tip {} at DAA {} is already at requested target",
            plan_label(&plan, path),
            current_tip,
            current_daa
        );
        return Ok(());
    }

    let removed = selected_chain_suffix(storage, target.index + 1, current_index)?;
    if removed.is_empty() {
        info!(
            "[startup-repair] plan {} no-op: no selected-chain blocks above target {} (DAA {})",
            plan_label(&plan, path),
            target.hash,
            target.daa
        );
        return Ok(());
    }

    warn!(
        "[startup-repair] plan {} rewinding selected chain from {} (DAA {}, index {}) to {} (DAA {}, index {}), removed_blocks={}, mark_disqualified={}, cleanup_block_data={}, dry_run={}",
        plan_label(&plan, path),
        current_tip,
        current_daa,
        current_index,
        target.hash,
        target.daa,
        target.index,
        removed.len(),
        plan.mark_removed_disqualified,
        plan.cleanup_removed_block_data,
        plan.dry_run
    );

    if plan.dry_run {
        return Ok(());
    }

    apply_selected_chain_rewind(db, storage, &removed, target, plan.mark_removed_disqualified)?;
    virtual_processor.resolve_virtual();

    if plan.cleanup_removed_block_data {
        cleanup_removed_block_data(db, storage, &removed)?;
    }

    warn!(
        "[startup-repair] plan {} completed: selected chain now targets {} (DAA {}, index {}), removed_blocks={}",
        plan_label(&plan, path),
        target.hash,
        target.daa,
        target.index,
        removed.len()
    );

    Ok(())
}

fn trigger_matches(storage: &Arc<ConsensusStorage>, plan: &StartupRepairPlan) -> RepairResult<bool> {
    if plan.trigger_blocks.is_empty() {
        return Ok(true);
    }

    for trigger in &plan.trigger_blocks {
        let hash = parse_hash(trigger, "triggerBlocks")?;
        let exists = storage
            .statuses_store
            .read()
            .has(hash)
            .map_err(|err| format!("startup repair failed checking trigger block {hash}: {err}"))?;
        if exists {
            info!("[startup-repair] matched trigger block {}", hash);
            return Ok(true);
        }
    }

    Ok(!plan.require_trigger_block())
}

fn resolve_target(storage: &Arc<ConsensusStorage>, plan: &StartupRepairPlan, current_index: u64) -> RepairResult<RepairTarget> {
    if let Some(hash_text) = plan.target_block_hash.as_ref() {
        let hash = parse_hash(hash_text, "targetBlockHash")?;
        let index = storage
            .selected_chain_store
            .read()
            .get_by_hash(hash)
            .map_err(|err| format!("startup repair targetBlockHash {hash} is not in the selected chain: {err}"))?;
        let daa = storage
            .headers_store
            .get_daa_score(hash)
            .map_err(|err| format!("startup repair failed reading targetBlockHash {hash} DAA: {err}"))?;
        return Ok(RepairTarget { index, hash, daa });
    }

    let target_daa = plan.target_daa().expect("validate requires target DAA or target hash");
    for index in (0..=current_index).rev() {
        let hash = storage
            .selected_chain_store
            .read()
            .get_by_index(index)
            .map_err(|err| format!("startup repair failed reading selected-chain index {index}: {err}"))?;
        let daa = storage
            .headers_store
            .get_daa_score(hash)
            .map_err(|err| format!("startup repair failed reading selected-chain block {hash} DAA: {err}"))?;
        if daa <= target_daa {
            return Ok(RepairTarget { index, hash, daa });
        }
    }

    Err(format!("startup repair could not find a selected-chain block at or before DAA {}", target_daa))
}

fn selected_chain_suffix(storage: &Arc<ConsensusStorage>, first_index: u64, last_index: u64) -> RepairResult<Vec<Hash>> {
    if first_index > last_index {
        return Ok(Vec::new());
    }

    let selected_chain = storage.selected_chain_store.read();
    let mut removed = Vec::with_capacity((last_index - first_index + 1) as usize);
    for index in (first_index..=last_index).rev() {
        let hash = selected_chain
            .get_by_index(index)
            .map_err(|err| format!("startup repair failed reading selected-chain index {index}: {err}"))?;
        removed.push(hash);
    }
    Ok(removed)
}

fn apply_selected_chain_rewind(
    db: &Arc<DB>,
    storage: &Arc<ConsensusStorage>,
    removed: &[Hash],
    target: RepairTarget,
    mark_removed_disqualified: bool,
) -> RepairResult<()> {
    let mut batch = WriteBatch::default();

    storage
        .selected_chain_store
        .write()
        .apply_changes(&mut batch, &ChainPath { added: vec![], removed: removed.to_vec() })
        .map_err(|err| format!("startup repair failed applying selected-chain rewind: {err}"))?;

    let target_blue_work = storage
        .ghostdag_primary_store
        .get_blue_work(target.hash)
        .map_err(|err| format!("startup repair failed reading target blue work for {}: {}", target.hash, err))?;
    storage
        .headers_selected_tip_store
        .write()
        .set_batch(&mut batch, SortableBlock::new(target.hash, target_blue_work))
        .map_err(|err| format!("startup repair failed setting header selected tip to {}: {}", target.hash, err))?;

    let current_body_tips: Vec<Hash> = storage
        .body_tips_store
        .read()
        .get()
        .map_err(|err| format!("startup repair failed reading body tips: {err}"))?
        .read()
        .iter()
        .copied()
        .collect();
    storage
        .body_tips_store
        .write()
        .update_tips_batch(&mut batch, &[target.hash], &current_body_tips)
        .map_err(|err| format!("startup repair failed setting body tip to {}: {}", target.hash, err))?;

    if mark_removed_disqualified {
        let mut statuses = storage.statuses_store.write();
        for hash in removed.iter().copied() {
            statuses
                .set_batch(&mut batch, hash, BlockStatus::StatusDisqualifiedFromChain)
                .map_err(|err| format!("startup repair failed marking {hash} disqualified: {err}"))?;
        }
    }

    db.write(batch).map_err(|err| format!("startup repair failed writing selected-chain rewind: {err}"))?;
    Ok(())
}

fn cleanup_removed_block_data(db: &Arc<DB>, storage: &Arc<ConsensusStorage>, removed: &[Hash]) -> RepairResult<()> {
    let mut batch = WriteBatch::default();
    for hash in removed.iter().copied() {
        ignore_missing(storage.block_transactions_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting block body for {hash}: {err}"))?;
        ignore_missing(storage.acceptance_data_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting acceptance data for {hash}: {err}"))?;
        ignore_missing(storage.utxo_diffs_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting UTXO diff for {hash}: {err}"))?;
        ignore_missing(storage.utxo_multisets_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting UTXO multiset for {hash}: {err}"))?;
        ignore_missing(storage.daa_excluded_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting DAA data for {hash}: {err}"))?;
        ignore_missing(storage.depth_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting depth data for {hash}: {err}"))?;
        ignore_missing(storage.atomic_state_store.delete_batch(&mut batch, hash))
            .map_err(|err| format!("startup repair failed deleting Atomic state for {hash}: {err}"))?;
    }

    db.write(batch).map_err(|err| format!("startup repair failed writing removed block cleanup: {err}"))?;
    Ok(())
}

fn ignore_missing(result: Result<(), StoreError>) -> Result<(), StoreError> {
    match result {
        Ok(()) | Err(StoreError::KeyNotFound(_)) => Ok(()),
        Err(err) => Err(err),
    }
}

fn parse_hash(value: &str, field: &str) -> RepairResult<Hash> {
    Hash::from_str(value.trim()).map_err(|err| format!("invalid {field} hash `{value}` in startup repair plan: {err}"))
}

fn plan_label<'a>(plan: &'a StartupRepairPlan, path: &'a Path) -> String {
    plan.name.clone().unwrap_or_else(|| path.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::StartupRepairPlan;

    #[test]
    fn parses_go_compatible_plan_schema() {
        let plan: StartupRepairPlan = serde_json::from_str(
            r#"{
                "schemaVersion": 1,
                "enabled": true,
                "name": "rewind-before-bad-selected-branch",
                "triggerBlocks": [
                    "30f4243e9a14e7c6f4c74f831794e7b6e2958c84225603db79ea14182a75fd49"
                ],
                "requireTriggerBlock": true,
                "targetDaa": 100000,
                "markRemovedDisqualified": true,
                "cleanupRemovedBlockData": true,
                "dryRun": false
            }"#,
        )
        .expect("plan should parse");

        plan.validate().expect("plan should be valid");
        assert!(plan.enabled);
        assert_eq!(plan.target_daa(), Some(100000));
        assert!(plan.require_trigger_block());
    }

    #[test]
    fn rejects_ambiguous_target() {
        let plan: StartupRepairPlan =
            serde_json::from_str(r#"{"schemaVersion":1,"targetDaa":100,"targetBlockHash":"30f4243e9a14e7c6f4c74f831794e7b6e2958c84225603db79ea14182a75fd49"}"#)
                .expect("plan should parse");
        assert!(plan.validate().is_err());
    }
}
