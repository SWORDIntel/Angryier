//! Independent concrete replay of a SAT-owned dynamic prefix from its pinned root.
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

use angryier_arch::Decoder;
use angryier_distribution::contracts::{CampaignManifest, Digest, WorkUnit};
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_provenance::sustained::{DynamicBlock, ReplayVerification, WitnessEvidence};

use super::{SymbolicSession, SymbolicState, trace_digest};

pub(crate) struct WitnessReplayInputs<'a> {
    pub(crate) model: &'a [(u64, Vec<u8>)],
    pub(crate) expected_trace: &'a [u64],
}

pub(crate) fn verify<D: Decoder>(
    session: &SymbolicSession<'_, D>,
    root: &SymbolicState,
    unit: &WorkUnit,
    manifest: &CampaignManifest,
    initial: Digest,
    inputs: WitnessReplayInputs<'_>,
    timeout: Duration,
) -> Option<WitnessEvidence> {
    let WitnessReplayInputs { model, expected_trace } = inputs;
    if timeout.is_zero()
        || manifest.spec.architecture != "x86_64"
        || !manifest.spec.inputs.is_empty()
        || !manifest.spec.stubs.is_empty()
        || unit.prefix.is_empty()
        || root.symbols.is_empty()
        || !root.replay_stream_symbols.is_empty()
        || !root.memory.memory.symbolic_writes().is_empty()
        || model.is_empty()
        || model.len() > 4096
        || expected_trace.is_empty()
        || expected_trace.len().saturating_mul(16) > manifest.spec.limits.max_trace_bytes as usize
    {
        return None;
    }
    let mut reg_seeds = BTreeMap::new();
    let mut mem_seeds = BTreeMap::new();
    for binding in &root.symbols {
        let expr_id = u64::from(binding.expression.0);
        if let Some(&addr) = root.replay_memory_symbols.get(&binding.expression) {
            if binding.width != 8 || mem_seeds.insert(expr_id, addr).is_some() {
                return None;
            }
        } else if binding.width != 64
            || !(crate::register_id::GPR_BASE..crate::register_id::GPR_BASE + 16).contains(&binding.register)
            || reg_seeds.insert(expr_id, binding.register).is_some()
        {
            return None;
        }
    }
    let mut registers = BTreeMap::new();
    let mut mem_bytes = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for (expr, value) in model {
        if !seen.insert(*expr)
            || value.is_empty()
            || value.len() > 16
            || value.get(8..).is_some_and(|upper| upper.iter().any(|byte| *byte != 0))
        {
            return None;
        }
        if let Some(&register) = reg_seeds.get(expr) {
            let mut bytes = [0; 8];
            bytes[..value.len().min(8)].copy_from_slice(&value[..value.len().min(8)]);
            if registers.insert(register, u64::from_le_bytes(bytes)).is_some() {
                return None;
            }
        } else if let Some(&addr) = mem_seeds.get(expr) {
            if value.get(1..).is_some_and(|upper| upper.iter().any(|byte| *byte != 0)) {
                return None;
            }
            if mem_bytes.insert(addr, value[0]).is_some() {
                return None;
            }
        } else {
            return None;
        }
    }
    if seen.len() != reg_seeds.len() + mem_seeds.len() {
        return None;
    }
    let mut input = b"angryier-sustained-register-input/v1".to_vec();
    for (register, value) in &registers {
        input.extend_from_slice(&register.to_le_bytes());
        input.extend_from_slice(&value.to_le_bytes());
    }
    if !mem_bytes.is_empty() {
        input.extend_from_slice(b"memory");
        input.extend_from_slice(&(mem_bytes.len() as u64).to_le_bytes());
        for (addr, byte) in &mem_bytes {
            input.extend_from_slice(&addr.to_le_bytes());
            input.push(*byte);
        }
    }
    let input_digest = Digest::of(&input);
    let mut provenance = b"angryier-sustained-concrete-replay/v1".to_vec();
    for digest in [
        manifest.campaign_digest,
        manifest.spec.binary_digest,
        initial,
        input_digest,
    ] {
        provenance.extend_from_slice(&digest.0);
    }
    let replay_input_provenance = Some(Digest::of(&provenance).0);
    let mut process = root.process.clone();
    for (register, value) in registers {
        if process.write_register(register, value).is_err() {
            return None;
        }
    }
    if !mem_bytes.is_empty() {
        let mut iter = mem_bytes.into_iter().peekable();
        while let Some((start, first)) = iter.next() {
            let mut run = vec![ByteValue::Concrete(first)];
            let mut next_addr = start.saturating_add(1);
            while let Some(&(addr, byte)) = iter.peek() {
                if addr != next_addr {
                    break;
                }
                iter.next();
                run.push(ByteValue::Concrete(byte));
                next_addr = next_addr.saturating_add(1);
            }
            let Ok(updated) = process.state.memory.write(start, &run) else {
                return None;
            };
            process.state.memory = updated;
        }
    }
    let mut visits = BTreeMap::<u64, u64>::new();
    let mut replay_trace = Vec::new();
    let mut next_branch = 0;
    let mut replay = ReplayVerification::Mismatch;
    let started = Instant::now();
    for (index, &expected_pc) in expected_trace.iter().enumerate() {
        if started.elapsed() >= timeout {
            replay = ReplayVerification::Error;
            break;
        }
        if process.terminated
            || process.pc().ok() != Some(expected_pc)
            || process.trace.as_slice() != &expected_trace[..index]
        {
            break;
        }
        let visit = visits.entry(expected_pc).or_default();
        let block = DynamicBlock {
            pc: expected_pc,
            visit_index: *visit,
        };
        *visit += 1;
        let expected = unit.prefix.get(next_branch);
        let at_branch = expected
            .is_some_and(|item| item.branch.branch_pc == expected_pc && item.branch.visit_index == block.visit_index);
        if let Some(item) = expected.filter(|_| at_branch) {
            let mut prefix = process.trace.clone();
            prefix.push(expected_pc);
            if trace_digest(&prefix) != item.branch.trace_digest {
                break;
            }
        }
        let step = session.runtime.step(&mut process);
        replay_trace.push(block);
        if step.is_err() {
            replay = ReplayVerification::Error;
            break;
        }
        if let Some(item) = expected.filter(|_| at_branch) {
            if process.pc().ok() != Some(item.target()) {
                break;
            }
            next_branch += 1;
        }
    }
    if started.elapsed() < timeout
        && next_branch == unit.prefix.len()
        && replay_trace.len() == expected_trace.len()
        && process.terminated
        && process.trace == expected_trace
    {
        replay = ReplayVerification::Verified {
            trace_digest: trace_digest(&process.trace).0,
        };
    }
    Some(WitnessEvidence {
        input_digest: input_digest.0,
        replay_input_provenance,
        replay_trace,
        replay,
    })
}
