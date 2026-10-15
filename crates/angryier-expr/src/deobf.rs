//! Deobfuscation-oriented iterative simplifier over the hash-consed
//! expression DAG.
//!
//! The arena already folds all-constant nodes and canonicalizes commutative
//! operand order at intern time, but mutated (obfuscated) code hides simple
//! identities behind *mixed* boolean/arithmetic shapes that no constant
//! folder can touch: MBA expressions such as `(x|y) + (x&y)`, negation
//! spelled `-1 - x`, redundant `x^c1^c2` chains, shifts standing in for
//! multiplications, and constants sprinkled through add/sub chains above
//! zero/sign extensions. This module rewrites those shapes bottom-up into
//! the short canonical forms a solver or a human expects.
//!
//! Every rule is semantics-preserving over the node's bitvector width. The
//! differential test at the bottom of this file pins that property by
//! evaluating randomly generated trees (seeded, deterministic) before and
//! after simplification.
//!
//! # Rule catalogue
//!
//! | Obfuscated shape | Rewritten to |
//! | --- | --- |
//! | `x + ~x` (either operand order, `~` in either spelling) | `-1` |
//! | `x - x`, `x ^ x` | `0` |
//! | `(x\|y) + (x&y)` | `x + y` |
//! | `(x\|y) - (x&y)` | `x ^ y` |
//! | `(x + c) ± k`, `(x - c) ± k`, `(c - x) ± k` | one folded constant |
//! | `not(not(x))` (either spelling) | `x` |
//! | `not(x)` | `-1 - x` (strength reduction) |
//! | `(x ^ c1) ^ c2` | `x ^ (c1 ⊕ c2)` |
//! | `x ^ 0`, `x + 0`, `x - 0`, `x & ~0`, `x \| 0`, `x * 1` | `x` |
//! | `x ^ ~0` | `-1 - x` (the not normal form) |
//! | `x & 0`, `x \| ~0`, `x * 0` | `0` / `~0` |
//! | `x & x`, `x \| x` | `x` |
//! | `x << k` (`k < width`) | `x * 2^k` |
//! | `x << k`, `x >>u k` with `k >= width` | `0` |
//! | `zext(zext(x))`, `sext(sext(x))` | single extension at outer width |
//! | `sext(zext(x))` | `zext(x)` at outer width |
//!
//! Add/sub constant chains also fold when the symbolic operand is an
//! extension, e.g. `(zext(x) + c1) + c2 -> zext(x) + (c1+c2)`. Pushing an
//! extension *through* wrap-around arithmetic is deliberately absent: it is
//! unsound (`zext_{8->16}(1) - 2 = 0xffff` but `zext(1-2) = 0x00ff`), so
//! only chain folding and extension self-composition are performed.
//!
//! # Normal forms and termination
//!
//! `not(x)` normalizes to `-1 - x`, and both spellings are recognized as
//! negation wherever a rule consumes one, so `not(-1 - x)` and
//! `-1 - (-1 - x)` collapse to `x` in a single visit. No rule ever emits a
//! `not` or a shift, so the counts of those nodes strictly decrease; every
//! other rewrite strictly reduces nested-constant/extension depth or node
//! count. One bottom-up pass with per-node local iteration therefore
//! reaches the fixpoint (each pattern inspects at most grandchildren, which
//! are final by the time a node is examined); the outer pass loop and
//! [`MAX_LOCAL_STEPS`] are defensive caps in case a future rule breaks that
//! invariant.
//!
//! # Fail-closed contract
//!
//! Only plain bitvector algebra is rewritten. Comparisons, `ite`,
//! `concat`/`extract`, rotates, divisions, and every non-bitvector sort
//! (bool, float, vector, opmask, tile) pass through with their children
//! rewritten. Widths above 128 skip rules needing `u128` arithmetic. Any
//! arena error (unknown operand, poisoned lock, replacement that fails
//! validation) leaves the offending node exactly as it was — a rewrite that
//! cannot be completed simply does not happen, so the returned id always
//! denotes the same value as the input.

use crate::{ExprArena, ExprId, ExprNode, ExprOp, ExprSort};
use angryier_types::fx::FxHashMap;

/// Cap on whole-tree fixpoint passes. One bottom-up pass with per-node local
/// iteration already reaches fixpoint for this rule set; the loop exits on
/// the second pass because the memo table makes it a no-op walk. 64 leaves
/// more than an order of magnitude of headroom over the deepest realistic
/// constant/extension chain while still guaranteeing termination if a future
/// rule re-introduces work.
const MAX_PASSES: usize = 64;

/// Cap on local rewrite iterations at a single node — a defense against a
/// rule pair that ping-pongs at one node. Observed cascades are short
/// (`x << 0` becomes `x * 1` then `x`), so 16 is ample.
const MAX_LOCAL_STEPS: usize = 16;

/// Iteratively simplifies `root` through the arena. Because the arena is
/// hash-consed, every rewrite is an *intern* of an equivalent, shorter node;
/// nothing is mutated or removed. Returns the id of the simplified
/// equivalent, which always denotes the same value (and carries the same
/// sort) as `root`.
pub fn deobfuscate<A: ExprArena + ?Sized>(arena: &A, root: ExprId) -> ExprId {
    let mut memo = FxHashMap::default();
    let mut current = root;
    for _ in 0..MAX_PASSES {
        let next = run_pass(arena, current, &mut memo);
        if next == current {
            return current;
        }
        current = next;
    }
    current
}

/// One bottom-up pass. `memo` caches original-id -> simplified-id across the
/// whole `deobfuscate` call, which both dedups shared DAG subtrees and makes
/// follow-up passes nearly free.
fn run_pass<A: ExprArena + ?Sized>(arena: &A, root: ExprId, memo: &mut FxHashMap<ExprId, ExprId>) -> ExprId {
    // Iterative post-order walk: expressions decoded from mutated code can
    // be far deeper than the default stack, so recursion is not an option.
    // `expanded` distinguishes "children pending" from "children finished".
    // Each expansion pushes its finish frame *below* its children's frames,
    // so a node is only ever finished once every operand is memoized.
    // Duplicate frames for a shared operand are fine: the first completes
    // and the rest become memo no-ops, and deduplicating them would break
    // that ordering guarantee.
    let mut stack = vec![(root, false)];
    while let Some((id, expanded)) = stack.pop() {
        if memo.contains_key(&id) {
            continue;
        }
        if expanded {
            finish(arena, id, memo);
            continue;
        }
        let Some(node) = arena.get(id) else {
            // Unknown operand: fail closed by passing the node through.
            memo.insert(id, id);
            continue;
        };
        stack.push((id, true));
        for &operand in &node.operands {
            if !memo.contains_key(&operand) {
                stack.push((operand, false));
            }
        }
    }
    memo.get(&root).copied().unwrap_or(root)
}

/// Completes a node whose children are all simplified: rebuilds it over the
/// simplified children, then applies local rewrites to fixpoint.
fn finish<A: ExprArena + ?Sized>(arena: &A, id: ExprId, memo: &mut FxHashMap<ExprId, ExprId>) {
    let Some(node) = arena.get(id) else {
        memo.insert(id, id);
        return;
    };
    let mut changed = false;
    let mut operands = Vec::with_capacity(node.operands.len());
    for &operand in &node.operands {
        let rewritten = memo.get(&operand).copied().unwrap_or(operand);
        changed |= rewritten != operand;
        operands.push(rewritten);
    }
    let mut current = id;
    if changed {
        let rebuilt = ExprNode {
            sort: node.sort,
            op: node.op,
            operands,
            immediate: node.immediate.clone(),
        };
        match arena.intern(rebuilt) {
            Ok(rewritten) => current = rewritten,
            // Interning the rebuilt node failed: the original node is its
            // own correct semantics, so keep it and stop rewriting here.
            Err(_) => {
                memo.insert(id, id);
                return;
            }
        }
    }
    for _ in 0..MAX_LOCAL_STEPS {
        let Some(current_node) = arena.get(current) else {
            break;
        };
        let Some(replacement) = rewrite_node(arena, &current_node) else {
            break;
        };
        match arena.intern(replacement) {
            Ok(next) if next != current => current = next,
            _ => break,
        }
    }
    memo.insert(id, current);
}

/// Dispatches one local rewrite. Children of `node` are already fully
/// simplified, so patterns may match against them (and their operands)
/// directly. Returns `None` to leave the node untouched.
fn rewrite_node<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode) -> Option<ExprNode> {
    // Only plain bitvector algebra is rewritten; everything else fails
    // closed (comparisons, compounds, rotates, divisions, other sorts).
    let ExprSort::BitVec(bits) = node.sort else {
        return None;
    };
    match node.op {
        ExprOp::Not => rewrite_not(arena, node, bits),
        ExprOp::Add => rewrite_add(arena, node, bits),
        ExprOp::Sub => rewrite_sub(arena, node, bits),
        ExprOp::Xor => rewrite_xor(arena, node, bits),
        ExprOp::And => rewrite_and(arena, node, bits),
        ExprOp::Or => rewrite_or(arena, node, bits),
        ExprOp::Mul => rewrite_mul(arena, node, bits),
        ExprOp::Shl => rewrite_shl(arena, node, bits),
        ExprOp::LShr => rewrite_lshr(arena, node, bits),
        ExprOp::ZExt | ExprOp::SExt => rewrite_extend(arena, node),
        _ => None,
    }
}

/// Widens a little-endian immediate to `u128` (mirrors the arena's private
/// reader, capped at 16 bytes).
fn widen(bytes: &[u8]) -> u128 {
    let mut widened = [0_u8; 16];
    let len = bytes.len().min(16);
    widened[..len].copy_from_slice(&bytes[..len]);
    u128::from_le_bytes(widened)
}

fn bit_mask(bits: u16) -> u128 {
    if bits >= 128 { u128::MAX } else { (1_u128 << bits) - 1 }
}

/// Canonical little-endian constant bytes for `value` at `bits`.
fn constant_bytes(value: u128, bits: u16) -> Vec<u8> {
    value.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec()
}

/// Canonical bitvector constant node for widths up to 128 bits.
fn constant_node(bits: u16, value: u128) -> ExprNode {
    ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Constant,
        operands: Vec::new(),
        immediate: constant_bytes(value, bits),
    }
}

/// Builds the all-ones constant (`-1`) byte-wise so it works at any
/// bitvector width, including widths above 128 that `u128` cannot represent.
fn all_ones_node(bits: u16) -> ExprNode {
    let mut immediate = vec![0xff; usize::from(bits).div_ceil(8)];
    let used = bits % 8;
    if used != 0 {
        let last = immediate.len() - 1;
        immediate[last] = 0xff_u8 << (8 - used);
    }
    ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Constant,
        operands: Vec::new(),
        immediate,
    }
}

fn zero_node(bits: u16) -> ExprNode {
    ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Constant,
        operands: Vec::new(),
        immediate: vec![0; usize::from(bits).div_ceil(8)],
    }
}

/// Byte-level zero test, valid at any width.
fn is_zero_const(node: &ExprNode) -> bool {
    node.op == ExprOp::Constant && node.immediate.iter().all(|&byte| byte == 0)
}

/// Byte-level one test, valid at any width.
fn is_one_const(node: &ExprNode) -> bool {
    node.op == ExprOp::Constant
        && node.immediate.first() == Some(&1)
        && node.immediate.iter().skip(1).all(|&byte| byte == 0)
}

/// Byte-level all-ones test, valid at any width.
fn is_all_ones(node: &ExprNode) -> bool {
    let ExprSort::BitVec(bits) = node.sort else {
        return false;
    };
    if node.op != ExprOp::Constant {
        return false;
    }
    let len = usize::from(bits).div_ceil(8);
    if node.immediate.len() != len {
        return false;
    }
    let used = bits % 8;
    let full = if used == 0 { len } else { len - 1 };
    node.immediate.iter().take(full).all(|&byte| byte == 0xff)
        && (used == 0 || node.immediate[len - 1] == 0xff_u8 << (8 - used))
}

/// Reads a bitvector constant of width <= 128 (arithmetic rules are skipped
/// above that width; byte-level rules still apply).
fn constant_value(node: &ExprNode) -> Option<u128> {
    if node.op != ExprOp::Constant {
        return None;
    }
    let ExprSort::BitVec(bits) = node.sort else {
        return None;
    };
    if bits > 128 {
        return None;
    }
    Some(widen(&node.immediate) & bit_mask(bits))
}

/// Recognizes both spellings of bitwise negation — a literal `not`, and the
/// strength-reduced `-1 - x` this module normalizes to — and returns the
/// negated operand.
fn not_operand<A: ExprArena + ?Sized>(arena: &A, id: ExprId) -> Option<ExprId> {
    let node = arena.get(id)?;
    if !matches!(node.sort, ExprSort::BitVec(_)) {
        return None;
    }
    match node.op {
        ExprOp::Not => node.operands.first().copied(),
        ExprOp::Sub => {
            let left = node.operands.first().copied()?;
            let right = node.operands.get(1).copied()?;
            let left_node = arena.get(left)?;
            if is_all_ones(&left_node) { Some(right) } else { None }
        }
        _ => None,
    }
}

/// Fetches the two operand nodes of a validated binary node.
fn binary_children<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode) -> Option<(ExprNode, ExprNode)> {
    Some((arena.get(*node.operands.first()?)?, arena.get(*node.operands.get(1)?)?))
}

/// Matches `or_node = (x|y)` against `and_node = (x&y)` over the same
/// operand pair. Commutative operands are canonically sorted at intern time,
/// so equal pairs compare equal as plain id lists.
fn or_and_pair(or_node: &ExprNode, and_node: &ExprNode) -> Option<Vec<ExprId>> {
    if or_node.op == ExprOp::Or && and_node.op == ExprOp::And && or_node.operands == and_node.operands {
        Some(or_node.operands.clone())
    } else {
        None
    }
}

/// `not(x) -> -1 - x`, with double negation collapsed first through either
/// spelling (`not(not(x))` and `not(-1 - x)` both yield `x`).
fn rewrite_not<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let inner = node.operands.first().copied()?;
    if let Some(negated) = not_operand(arena, inner) {
        return arena.get(negated);
    }
    let ones = arena.intern(all_ones_node(bits)).ok()?;
    Some(ExprNode {
        sort: node.sort,
        op: ExprOp::Sub,
        operands: vec![ones, inner],
        immediate: Vec::new(),
    })
}

fn rewrite_add<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    let (x, y) = (node.operands.first().copied()?, node.operands.get(1).copied()?);
    if is_zero_const(&b) {
        return Some(a);
    }
    if is_zero_const(&a) {
        return Some(b);
    }
    // x + ~x = -1, with `~` in either spelling and on either side.
    if not_operand(arena, x) == Some(y) || not_operand(arena, y) == Some(x) {
        return Some(all_ones_node(bits));
    }
    // (x|y) + (x&y) = x + y (the carry-save identity holds mod 2^n).
    if let Some(pair) = or_and_pair(&a, &b).or_else(|| or_and_pair(&b, &a)) {
        return Some(ExprNode {
            sort: node.sort,
            op: ExprOp::Add,
            operands: pair,
            immediate: Vec::new(),
        });
    }
    chain_through(arena, node, bits, ExprOp::Add)
}

fn rewrite_sub<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    let (x, y) = (node.operands.first().copied()?, node.operands.get(1).copied()?);
    if x == y {
        return Some(zero_node(bits));
    }
    if is_zero_const(&b) {
        return Some(a);
    }
    // (x|y) - (x&y) = x ^ y: the and-bits are a subset of the or-bits, so
    // the subtraction never borrows.
    if let Some(pair) = or_and_pair(&a, &b) {
        return Some(ExprNode {
            sort: node.sort,
            op: ExprOp::Xor,
            operands: pair,
            immediate: Vec::new(),
        });
    }
    chain_through(arena, node, bits, ExprOp::Sub)
}

fn rewrite_xor<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    let (x, y) = (node.operands.first().copied()?, node.operands.get(1).copied()?);
    if x == y {
        return Some(zero_node(bits));
    }
    if is_zero_const(&b) {
        return Some(a);
    }
    if is_zero_const(&a) {
        return Some(b);
    }
    // (x ^ c1) ^ c2 -> x ^ (c1 ^ c2), both alignments. This runs before the
    // all-ones case so `x ^ c ^ -1` folds its constants first.
    if let Some(k) = constant_value(&b)
        && a.op == ExprOp::Xor
        && let Some(rewritten) = xor_chain(arena, bits, &a, k)
    {
        return Some(rewritten);
    }
    if let Some(k) = constant_value(&a)
        && b.op == ExprOp::Xor
        && let Some(rewritten) = xor_chain(arena, bits, &b, k)
    {
        return Some(rewritten);
    }
    // x ^ -1 = ~x, spelled in the module's strength-reduced normal form.
    if is_all_ones(&b) || is_all_ones(&a) {
        let other = if is_all_ones(&b) { x } else { y };
        let ones = arena.intern(all_ones_node(bits)).ok()?;
        return Some(ExprNode {
            sort: node.sort,
            op: ExprOp::Sub,
            operands: vec![ones, other],
            immediate: Vec::new(),
        });
    }
    None
}

/// Folds `(x ^ c) ^ k` into `x ^ (c ^ k)`; the arena folds the re-interned
/// constants, and a cancelling pair (`c == k`) yields plain `x`.
fn xor_chain<A: ExprArena + ?Sized>(arena: &A, bits: u16, xor_node: &ExprNode, k: u128) -> Option<ExprNode> {
    let (l, r) = (xor_node.operands.first().copied()?, xor_node.operands.get(1).copied()?);
    let l_node = arena.get(l)?;
    let r_node = arena.get(r)?;
    let (x, c) = if let Some(c) = constant_value(&l_node) {
        (r, c)
    } else {
        constant_value(&r_node).map(|c| (l, c))?
    };
    let folded = c ^ k;
    if folded == 0 {
        return arena.get(x);
    }
    let folded_const = arena.intern(constant_node(bits, folded)).ok()?;
    Some(ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Xor,
        operands: vec![x, folded_const],
        immediate: Vec::new(),
    })
}

fn rewrite_and<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    let (x, y) = (node.operands.first().copied()?, node.operands.get(1).copied()?);
    if x == y {
        return Some(a);
    }
    if is_zero_const(&a) || is_zero_const(&b) {
        return Some(zero_node(bits));
    }
    if is_all_ones(&b) {
        return Some(a);
    }
    if is_all_ones(&a) {
        return Some(b);
    }
    None
}

fn rewrite_or<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    let (x, y) = (node.operands.first().copied()?, node.operands.get(1).copied()?);
    if x == y {
        return Some(a);
    }
    if is_all_ones(&a) || is_all_ones(&b) {
        return Some(all_ones_node(bits));
    }
    if is_zero_const(&b) {
        return Some(a);
    }
    if is_zero_const(&a) {
        return Some(b);
    }
    None
}

fn rewrite_mul<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (a, b) = binary_children(arena, node)?;
    if is_zero_const(&a) || is_zero_const(&b) {
        return Some(zero_node(bits));
    }
    if is_one_const(&b) {
        return Some(a);
    }
    if is_one_const(&a) {
        return Some(b);
    }
    None
}

/// `x << k` with constant `k`: a shift at or beyond the width is zero
/// (matching the arena's own constant-fold semantics); otherwise the shift
/// becomes a multiplication by `2^k`, which canonicalizes the shift/mul
/// mixing MBA mutations produce. `k == 0` cascades to `x` through the
/// `x * 1` identity on the next local step.
fn rewrite_shl<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let value = node.operands.first().copied()?;
    let (_, count) = binary_children(arena, node)?;
    let k = constant_value(&count)?;
    if k >= u128::from(bits) {
        return Some(zero_node(bits));
    }
    let product = arena.intern(constant_node(bits, 1_u128 << k)).ok()?;
    Some(ExprNode {
        sort: node.sort,
        op: ExprOp::Mul,
        operands: vec![value, product],
        immediate: Vec::new(),
    })
}

/// `x >>u k` with constant `k >= width` is zero. Smaller shifts have no
/// sound multiplicative form (rounding), and arithmetic shifts depend on
/// the sign, so they are left alone.
fn rewrite_lshr<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16) -> Option<ExprNode> {
    let (_, count) = binary_children(arena, node)?;
    let k = constant_value(&count)?;
    if k >= u128::from(bits) {
        return Some(zero_node(bits));
    }
    None
}

/// Extensions compose: `ext(ext(x))` collapses to one extension at the
/// outer width, and `sext(zext(x))` is a plain `zext` because the sign bit
/// the outer `sext` would replicate sits above the `zext`'s zero-fill
/// region, so it is always zero.
fn rewrite_extend<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode) -> Option<ExprNode> {
    let inner = node.operands.first().copied()?;
    let inner_node = arena.get(inner)?;
    match (node.op, inner_node.op) {
        (ExprOp::ZExt, ExprOp::ZExt) | (ExprOp::SExt, ExprOp::SExt) => Some(ExprNode {
            sort: node.sort,
            op: node.op,
            operands: inner_node.operands.clone(),
            immediate: Vec::new(),
        }),
        (ExprOp::SExt, ExprOp::ZExt) => Some(ExprNode {
            sort: node.sort,
            op: ExprOp::ZExt,
            operands: inner_node.operands.clone(),
            immediate: Vec::new(),
        }),
        _ => None,
    }
}

/// Tries the constant-chain fold for both operand alignments of the outer
/// node: `(p ± c) OP k` with `k` the constant operand.
fn chain_through<A: ExprArena + ?Sized>(arena: &A, node: &ExprNode, bits: u16, outer: ExprOp) -> Option<ExprNode> {
    let first = *node.operands.first()?;
    let second = *node.operands.get(1)?;
    // `k_on_right` records whether the constant `k` is the outer node's
    // second operand — for the non-commutative Sub this distinguishes
    // `p - k` from `k - p`.
    for (p, k, k_on_right) in [(first, second, true), (second, first, false)] {
        let p_node = arena.get(p)?;
        let k_node = arena.get(k)?;
        let Some(k_value) = constant_value(&k_node) else {
            continue;
        };
        if let Some(rewritten) = fold_constant_chain(arena, node.sort, bits, outer, k_on_right, &p_node, k_value) {
            return Some(rewritten);
        }
    }
    None
}

/// Folds a constant across one add/sub level. All rearrangements below are
/// exact in the ring mod 2^bits, so no borrow/carry reasoning is needed.
/// With `k` the outer constant operand and `p` the other operand:
///
/// *outer = p OP k* (`OP` is `+` or `-`):
///
/// * `(x + c) OP k = x + (c ± k)`   (const on either side of `p`)
/// * `(x - c) OP k = x - (c ∓ k)`
/// * `(c - x) OP k = (c ± k) - x`
///
/// *outer = k - p* (constant on the left of a sub):
///
/// * `k - (x + c) = (k - c) - x`
/// * `k - (x - c) = (k + c) - x`
/// * `k - (c - x) = (k - c) + x`
///
/// The last row is the "subtract-from-constant chain" shape
/// `c1 - (c2 - x)` flattened to a single constant.
fn fold_constant_chain<A: ExprArena + ?Sized>(
    arena: &A,
    sort: ExprSort,
    bits: u16,
    outer: ExprOp,
    k_on_right: bool,
    p: &ExprNode,
    k: u128,
) -> Option<ExprNode> {
    let make = |op: ExprOp, left: ExprId, right: ExprId| ExprNode {
        sort,
        op,
        operands: vec![left, right],
        immediate: Vec::new(),
    };
    let new_const = |value: u128| -> Option<ExprId> {
        arena
            .intern(ExprNode {
                sort,
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: constant_bytes(value, bits),
            })
            .ok()
    };
    let value = |id: ExprId| -> Option<u128> { arena.get(id).and_then(|n| constant_value(&n)) };

    let (p_op, p_left, p_right) = (p.op, p.operands.first().copied()?, p.operands.get(1).copied()?);
    let left_is_const = arena.op_of(p_left) == Some(ExprOp::Constant);
    let right_is_const = arena.op_of(p_right) == Some(ExprOp::Constant);

    match (outer, k_on_right) {
        // outer = p + k, or outer = p - k with k on the right.
        (ExprOp::Add, _) | (ExprOp::Sub, true) => {
            let add_k = outer == ExprOp::Add;
            match (p_op, left_is_const, right_is_const) {
                // (x + c) OP k, constant on either side of p.
                (ExprOp::Add, false, true) => {
                    let c = value(p_right)?;
                    let folded = if add_k { c.wrapping_add(k) } else { c.wrapping_sub(k) };
                    Some(make(ExprOp::Add, p_left, new_const(folded)?))
                }
                (ExprOp::Add, true, false) => {
                    let c = value(p_left)?;
                    let folded = if add_k { c.wrapping_add(k) } else { c.wrapping_sub(k) };
                    Some(make(ExprOp::Add, p_right, new_const(folded)?))
                }
                // (x - c) OP k
                (ExprOp::Sub, false, true) => {
                    let c = value(p_right)?;
                    let folded = if add_k { c.wrapping_sub(k) } else { c.wrapping_add(k) };
                    Some(make(ExprOp::Sub, p_left, new_const(folded)?))
                }
                // (c - x) OP k
                (ExprOp::Sub, true, false) => {
                    let c = value(p_left)?;
                    let folded = if add_k { c.wrapping_add(k) } else { c.wrapping_sub(k) };
                    Some(make(ExprOp::Sub, new_const(folded)?, p_right))
                }
                _ => None,
            }
        }
        // outer = k - p, with the constant on the left of the sub.
        (ExprOp::Sub, false) => match (p_op, left_is_const, right_is_const) {
            // k - (x + c) = (k - c) - x
            (ExprOp::Add, false, true) => {
                let c = value(p_right)?;
                Some(make(ExprOp::Sub, new_const(k.wrapping_sub(c))?, p_left))
            }
            (ExprOp::Add, true, false) => {
                let c = value(p_left)?;
                Some(make(ExprOp::Sub, new_const(k.wrapping_sub(c))?, p_right))
            }
            // k - (x - c) = (k + c) - x
            (ExprOp::Sub, false, true) => {
                let c = value(p_right)?;
                Some(make(ExprOp::Sub, new_const(k.wrapping_add(c))?, p_left))
            }
            // k - (c - x) = (k - c) + x
            (ExprOp::Sub, true, false) => {
                let c = value(p_left)?;
                Some(make(ExprOp::Add, p_right, new_const(k.wrapping_sub(c))?))
            }
            _ => None,
        },
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExprArenaError, ShardedExprArena};
    use angryier_types::ExpressionNormalizationVersion;

    fn arena() -> ShardedExprArena {
        ShardedExprArena::new(ExpressionNormalizationVersion(1))
    }

    fn symbol(arena: &ShardedExprArena, source: u64, bits: u16) -> Result<ExprId, ExprArenaError> {
        arena.intern(ExprNode {
            sort: ExprSort::BitVec(bits),
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: source.to_le_bytes().to_vec(),
        })
    }

    fn konst(arena: &ShardedExprArena, value: u128, bits: u16) -> Result<ExprId, ExprArenaError> {
        arena.intern(constant_node(bits, value & bit_mask(bits)))
    }

    fn binary(
        arena: &ShardedExprArena,
        op: ExprOp,
        left: ExprId,
        right: ExprId,
        bits: u16,
    ) -> Result<ExprId, ExprArenaError> {
        arena.intern(ExprNode {
            sort: ExprSort::BitVec(bits),
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
    }

    fn unary(arena: &ShardedExprArena, op: ExprOp, operand: ExprId, bits: u16) -> Result<ExprId, ExprArenaError> {
        arena.intern(ExprNode {
            sort: ExprSort::BitVec(bits),
            op,
            operands: vec![operand],
            immediate: Vec::new(),
        })
    }

    fn extension(
        arena: &ShardedExprArena,
        op: ExprOp,
        operand: ExprId,
        to_bits: u16,
    ) -> Result<ExprId, ExprArenaError> {
        arena.intern(ExprNode {
            sort: ExprSort::BitVec(to_bits),
            op,
            operands: vec![operand],
            immediate: Vec::new(),
        })
    }

    /// Reads a simplified node back as a bitvector constant value, so tests
    /// can assert exact folded results with plain `assert_eq!`.
    fn const_value_of(arena: &ShardedExprArena, id: ExprId) -> Option<u128> {
        arena
            .get(id)
            .filter(|n| n.op == ExprOp::Constant)
            .map(|n| widen(&n.immediate))
    }

    #[test]
    fn add_not_self_is_all_ones() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 32)?;
        let not_x = unary(&arena, ExprOp::Not, x, 32)?;
        let root = binary(&arena, ExprOp::Add, x, not_x, 32)?;
        assert_eq!(const_value_of(&arena, deobfuscate(&arena, root)), Some(bit_mask(32)));

        // Operand order must not matter.
        let commuted = binary(&arena, ExprOp::Add, not_x, x, 32)?;
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, commuted)),
            Some(bit_mask(32))
        );
        Ok(())
    }

    #[test]
    fn add_strength_reduced_not_self_is_all_ones() -> Result<(), ExprArenaError> {
        // ~x spelled as -1 - x must be recognized as negation too.
        let arena = arena();
        let x = symbol(&arena, 1, 16)?;
        let ones = konst(&arena, bit_mask(16), 16)?;
        let neg = binary(&arena, ExprOp::Sub, ones, x, 16)?;
        let root = binary(&arena, ExprOp::Add, neg, x, 16)?;
        assert_eq!(const_value_of(&arena, deobfuscate(&arena, root)), Some(bit_mask(16)));
        Ok(())
    }

    #[test]
    fn sub_self_is_zero() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 7, 8)?;
        let root = binary(&arena, ExprOp::Sub, x, x, 8)?;
        assert_eq!(const_value_of(&arena, deobfuscate(&arena, root)), Some(0));
        Ok(())
    }

    #[test]
    fn double_not_collapses_through_both_spellings() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 3, 64)?;
        let not_not = unary(&arena, ExprOp::Not, unary(&arena, ExprOp::Not, x, 64)?, 64)?;
        assert_eq!(deobfuscate(&arena, not_not), x);

        let ones = konst(&arena, bit_mask(64), 64)?;
        let sub_form = binary(&arena, ExprOp::Sub, ones, x, 64)?;
        let not_of_sub = unary(&arena, ExprOp::Not, sub_form, 64)?;
        assert_eq!(deobfuscate(&arena, not_of_sub), x);
        Ok(())
    }

    #[test]
    fn not_strength_reduces_to_sub_from_minus_one() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 5, 32)?;
        let not_x = unary(&arena, ExprOp::Not, x, 32)?;
        let ones = konst(&arena, bit_mask(32), 32)?;
        let expected = binary(&arena, ExprOp::Sub, ones, x, 32)?;
        assert_eq!(deobfuscate(&arena, not_x), expected);
        Ok(())
    }

    #[test]
    fn or_and_add_rewrites_to_plain_add() -> Result<(), ExprArenaError> {
        let arena = arena();
        let (x, y) = (symbol(&arena, 1, 16)?, symbol(&arena, 2, 16)?);
        let or = binary(&arena, ExprOp::Or, x, y, 16)?;
        let and = binary(&arena, ExprOp::And, x, y, 16)?;
        let expected = binary(&arena, ExprOp::Add, x, y, 16)?;

        let root = binary(&arena, ExprOp::Add, or, and, 16)?;
        assert_eq!(deobfuscate(&arena, root), expected);
        // Operand order must not matter.
        let commuted = binary(&arena, ExprOp::Add, and, or, 16)?;
        assert_eq!(deobfuscate(&arena, commuted), expected);
        Ok(())
    }

    #[test]
    fn or_and_sub_rewrites_to_xor() -> Result<(), ExprArenaError> {
        let arena = arena();
        let (x, y) = (symbol(&arena, 1, 16)?, symbol(&arena, 2, 16)?);
        let or = binary(&arena, ExprOp::Or, x, y, 16)?;
        let and = binary(&arena, ExprOp::And, x, y, 16)?;
        let expected = binary(&arena, ExprOp::Xor, x, y, 16)?;

        let root = binary(&arena, ExprOp::Sub, or, and, 16)?;
        assert_eq!(deobfuscate(&arena, root), expected);
        Ok(())
    }

    #[test]
    fn xor_const_chain_folds() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 32)?;
        let (c1, c2) = (0x1234_5678_u128, 0x9abc_def0_u128);
        let inner = binary(&arena, ExprOp::Xor, x, konst(&arena, c1, 32)?, 32)?;
        let root = binary(&arena, ExprOp::Xor, inner, konst(&arena, c2, 32)?, 32)?;
        let expected = binary(&arena, ExprOp::Xor, x, konst(&arena, c1 ^ c2, 32)?, 32)?;
        assert_eq!(deobfuscate(&arena, root), expected);
        Ok(())
    }

    #[test]
    fn xor_const_chain_cancels_to_identity() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 8)?;
        let inner = binary(&arena, ExprOp::Xor, x, konst(&arena, 0x5a, 8)?, 8)?;
        let root = binary(&arena, ExprOp::Xor, inner, konst(&arena, 0x5a, 8)?, 8)?;
        assert_eq!(deobfuscate(&arena, root), x);
        Ok(())
    }

    #[test]
    fn xor_identities() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 8)?;
        assert_eq!(
            deobfuscate(&arena, binary(&arena, ExprOp::Xor, x, konst(&arena, 0, 8)?, 8)?),
            x
        );
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::Xor, x, x, 8)?)),
            Some(0)
        );

        // x ^ -1 becomes the strength-reduced negation.
        let ones = konst(&arena, bit_mask(8), 8)?;
        let expected = binary(&arena, ExprOp::Sub, ones, x, 8)?;
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Xor, x, ones, 8)?), expected);
        Ok(())
    }

    #[test]
    fn subtract_from_constant_chain_folds() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 32)?;
        let (c1, c2) = (1000_u128, 37_u128);
        let inner = binary(&arena, ExprOp::Sub, konst(&arena, c2, 32)?, x, 32)?;
        let root = binary(&arena, ExprOp::Sub, konst(&arena, c1, 32)?, inner, 32)?;
        let expected = binary(&arena, ExprOp::Add, x, konst(&arena, c1.wrapping_sub(c2), 32)?, 32)?;
        assert_eq!(deobfuscate(&arena, root), expected);
        Ok(())
    }

    #[test]
    fn add_sub_constant_chains_fold() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 16)?;
        let (c1, c2) = (300_u128, 45_u128);
        let x_plus_c1 = binary(&arena, ExprOp::Add, x, konst(&arena, c1, 16)?, 16)?;
        let x_minus_c1 = binary(&arena, ExprOp::Sub, x, konst(&arena, c1, 16)?, 16)?;

        assert_eq!(
            deobfuscate(
                &arena,
                binary(&arena, ExprOp::Add, x_plus_c1, konst(&arena, c2, 16)?, 16)?
            ),
            binary(&arena, ExprOp::Add, x, konst(&arena, c1 + c2, 16)?, 16)?
        );
        assert_eq!(
            deobfuscate(
                &arena,
                binary(&arena, ExprOp::Sub, x_plus_c1, konst(&arena, c2, 16)?, 16)?
            ),
            binary(&arena, ExprOp::Add, x, konst(&arena, c1 - c2, 16)?, 16)?
        );
        assert_eq!(
            deobfuscate(
                &arena,
                binary(&arena, ExprOp::Add, x_minus_c1, konst(&arena, c2, 16)?, 16)?
            ),
            binary(&arena, ExprOp::Sub, x, konst(&arena, c1 - c2, 16)?, 16)?
        );
        assert_eq!(
            deobfuscate(
                &arena,
                binary(&arena, ExprOp::Sub, x_minus_c1, konst(&arena, c2, 16)?, 16)?
            ),
            binary(&arena, ExprOp::Sub, x, konst(&arena, c1 + c2, 16)?, 16)?
        );
        Ok(())
    }

    #[test]
    fn constant_chain_folds_through_zext() -> Result<(), ExprArenaError> {
        // (zext(x) + c1) + c2 -> zext(x) + (c1+c2): the extension is just the
        // symbolic leaf of the chain; pushing it *through* the wrap-around
        // add would be unsound and is deliberately not attempted.
        let arena = arena();
        let x8 = symbol(&arena, 1, 8)?;
        let wide = extension(&arena, ExprOp::ZExt, x8, 32)?;
        let plus = binary(&arena, ExprOp::Add, wide, konst(&arena, 700, 32)?, 32)?;
        let root = binary(&arena, ExprOp::Add, plus, konst(&arena, 41, 32)?, 32)?;
        let expected = binary(&arena, ExprOp::Add, wide, konst(&arena, 741, 32)?, 32)?;
        assert_eq!(deobfuscate(&arena, root), expected);
        Ok(())
    }

    #[test]
    fn extensions_self_compose() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 4)?;
        let mid_z = extension(&arena, ExprOp::ZExt, x, 16)?;
        let mid_s = extension(&arena, ExprOp::SExt, x, 16)?;

        assert_eq!(
            deobfuscate(&arena, extension(&arena, ExprOp::ZExt, mid_z, 64)?),
            extension(&arena, ExprOp::ZExt, x, 64)?
        );
        assert_eq!(
            deobfuscate(&arena, extension(&arena, ExprOp::SExt, mid_s, 64)?),
            extension(&arena, ExprOp::SExt, x, 64)?
        );
        // The sign bit an outer sext would replicate is above the zext fill
        // region, hence always zero: sext(zext(x)) = zext(x).
        assert_eq!(
            deobfuscate(&arena, extension(&arena, ExprOp::SExt, mid_z, 64)?),
            extension(&arena, ExprOp::ZExt, x, 64)?
        );
        Ok(())
    }

    #[test]
    fn shl_becomes_multiplication() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 32)?;
        let root = binary(&arena, ExprOp::Shl, x, konst(&arena, 3, 8)?, 32)?;
        let expected = binary(&arena, ExprOp::Mul, x, konst(&arena, 8, 32)?, 32)?;
        assert_eq!(deobfuscate(&arena, root), expected);

        // Shift by zero cascades to the identity via x * 1.
        let zero_shift = binary(&arena, ExprOp::Shl, x, konst(&arena, 0, 8)?, 32)?;
        assert_eq!(deobfuscate(&arena, zero_shift), x);
        Ok(())
    }

    #[test]
    fn shift_past_width_folds_to_zero() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 8)?;
        let big = konst(&arena, 9, 8)?;
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::Shl, x, big, 8)?)),
            Some(0)
        );
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::LShr, x, big, 8)?)),
            Some(0)
        );
        // Arithmetic shifts past the width depend on the sign bit and must
        // pass through untouched.
        let ashr = binary(&arena, ExprOp::AShr, x, big, 8)?;
        assert_eq!(deobfuscate(&arena, ashr), ashr);
        Ok(())
    }

    #[test]
    fn boolean_and_multiplicative_identities() -> Result<(), ExprArenaError> {
        let arena = arena();
        let x = symbol(&arena, 1, 16)?;
        let zero = konst(&arena, 0, 16)?;
        let ones = konst(&arena, bit_mask(16), 16)?;
        let one = konst(&arena, 1, 16)?;

        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::And, x, x, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Or, x, x, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::And, x, ones, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Or, x, zero, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Add, x, zero, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Sub, x, zero, 16)?), x);
        assert_eq!(deobfuscate(&arena, binary(&arena, ExprOp::Mul, x, one, 16)?), x);
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::And, x, zero, 16)?)),
            Some(0)
        );
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::Or, x, ones, 16)?)),
            Some(bit_mask(16))
        );
        assert_eq!(
            const_value_of(&arena, deobfuscate(&arena, binary(&arena, ExprOp::Mul, x, zero, 16)?)),
            Some(0)
        );
        Ok(())
    }

    #[test]
    fn unknown_ops_pass_through_with_children_rewritten() -> Result<(), ExprArenaError> {
        let arena = arena();
        let (x, y) = (symbol(&arena, 1, 32)?, symbol(&arena, 2, 32)?);
        let condition = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![x, y],
            immediate: Vec::new(),
        })?;
        let x_plus_not_x = binary(&arena, ExprOp::Add, x, unary(&arena, ExprOp::Not, x, 32)?, 32)?;
        let root = arena.intern(ExprNode {
            sort: ExprSort::BitVec(32),
            op: ExprOp::Ite,
            operands: vec![condition, x_plus_not_x, y],
            immediate: Vec::new(),
        })?;

        // The ite itself is structurally untouched...
        let simplified = deobfuscate(&arena, root);
        let node = arena.get(simplified);
        assert!(matches!(
            node,
            Some(ExprNode {
                op: ExprOp::Ite,
                operands: ref ops,
                ..
            }) if ops.len() == 3
        ));
        // ...but its branch was rewritten to -1.
        if let Some(node) = arena.get(simplified) {
            assert_eq!(const_value_of(&arena, node.operands[1]), Some(bit_mask(32)));
        }

        // Divisions are never rewritten.
        let div = binary(&arena, ExprOp::UDiv, x, y, 32)?;
        assert_eq!(deobfuscate(&arena, div), div);
        Ok(())
    }

    #[test]
    fn non_bitvector_sorts_pass_through() -> Result<(), ExprArenaError> {
        let arena = arena();
        let vector_sort = ExprSort::Vector {
            lanes: 4,
            lane_bits: 32,
        };
        let vector_sym = arena.intern(ExprNode {
            sort: vector_sort,
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: 9_u64.to_le_bytes().to_vec(),
        })?;
        let root = arena.intern(ExprNode {
            sort: vector_sort,
            op: ExprOp::Add,
            operands: vec![vector_sym, vector_sym],
            immediate: Vec::new(),
        })?;
        assert_eq!(deobfuscate(&arena, root), root);
        Ok(())
    }

    #[test]
    fn unknown_root_returns_itself() {
        let arena = arena();
        assert_eq!(deobfuscate(&arena, ExprId(4242)), ExprId(4242));
    }

    #[test]
    fn constant_root_is_unchanged() -> Result<(), ExprArenaError> {
        let arena = arena();
        let root = konst(&arena, 0xbeef, 16)?;
        assert_eq!(deobfuscate(&arena, root), root);
        Ok(())
    }

    #[test]
    fn deep_constant_chain_fully_folds_without_recursion() -> Result<(), ExprArenaError> {
        // A deep left-nested chain exercises the iterative (non-recursive)
        // traversal; one pass must fold every level.
        let arena = arena();
        let x = symbol(&arena, 1, 32)?;
        let mut current = x;
        for _ in 0..1000 {
            current = binary(&arena, ExprOp::Add, current, konst(&arena, 1, 32)?, 32)?;
        }
        let simplified = deobfuscate(&arena, current);
        let expected = binary(&arena, ExprOp::Add, x, konst(&arena, 1000, 32)?, 32)?;
        assert_eq!(simplified, expected);
        Ok(())
    }

    // ---- differential test infrastructure --------------------------------

    /// Deterministic xorshift64* generator; the fixed seed keeps the
    /// differential test reproducible.
    struct Rng(u64);

    impl Rng {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next_u64() % bound
        }
    }

    /// Test-only constant evaluator mirroring the arena's own folding
    /// semantics (width masking, shift-by-value, rotate mod width, signed
    /// comparisons sign-extended from the operand width). Division by zero
    /// evaluates to 0; that convention is only ever compared against itself
    /// because rewrites never change an operand's *value*, so relative
    /// equality still pins semantics.
    fn evaluate(arena: &ShardedExprArena, id: ExprId, env: &FxHashMap<u64, u128>) -> Option<u128> {
        let node = arena.get(id)?;
        let signed = |value: u128, bits: u16| -> i128 {
            if bits > 0 && bits < 128 && value & (1_u128 << (bits - 1)) != 0 {
                (value | !bit_mask(bits)) as i128
            } else {
                value as i128
            }
        };
        match node.op {
            ExprOp::Constant => match node.sort {
                ExprSort::Bool => Some(u128::from(node.immediate.first().copied().unwrap_or(0))),
                ExprSort::BitVec(bits) => Some(widen(&node.immediate) & bit_mask(bits)),
                _ => None,
            },
            ExprOp::Symbol => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let bytes: [u8; 8] = node.immediate.as_slice().try_into().ok()?;
                Some(env.get(&u64::from_le_bytes(bytes)).copied().unwrap_or(0) & bit_mask(bits))
            }
            ExprOp::Add | ExprOp::Sub | ExprOp::Mul | ExprOp::And | ExprOp::Or | ExprOp::Xor => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let left = evaluate(arena, node.operands[0], env)?;
                let right = evaluate(arena, node.operands[1], env)?;
                let value = match node.op {
                    ExprOp::Add => left.wrapping_add(right),
                    ExprOp::Sub => left.wrapping_sub(right),
                    ExprOp::Mul => left.wrapping_mul(right),
                    ExprOp::And => left & right,
                    ExprOp::Or => left | right,
                    _ => left ^ right,
                };
                Some(value & bit_mask(bits))
            }
            ExprOp::Not => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                Some(!evaluate(arena, node.operands[0], env)? & bit_mask(bits))
            }
            ExprOp::Shl | ExprOp::LShr | ExprOp::AShr => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let left = evaluate(arena, node.operands[0], env)?;
                let shift = evaluate(arena, node.operands[1], env)?;
                let value = if shift >= u128::from(bits) {
                    match node.op {
                        ExprOp::AShr => {
                            if signed(left, bits) < 0 {
                                bit_mask(bits)
                            } else {
                                0
                            }
                        }
                        _ => 0,
                    }
                } else {
                    match node.op {
                        ExprOp::Shl => (left << shift) & bit_mask(bits),
                        ExprOp::LShr => (left >> shift) & bit_mask(bits),
                        _ => ((signed(left, bits) >> shift) as u128) & bit_mask(bits),
                    }
                };
                Some(value)
            }
            ExprOp::RotL | ExprOp::RotR => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let value = evaluate(arena, node.operands[0], env)?;
                let count = evaluate(arena, node.operands[1], env)?;
                let amount = (count % u128::from(bits)) as u32;
                let rotated = if amount == 0 {
                    value
                } else if node.op == ExprOp::RotL {
                    (value << amount) | (value >> (u32::from(bits) - amount))
                } else {
                    (value >> amount) | (value << (u32::from(bits) - amount))
                };
                Some(rotated & bit_mask(bits))
            }
            ExprOp::Eq => Some(u128::from(
                evaluate(arena, node.operands[0], env)? == evaluate(arena, node.operands[1], env)?,
            )),
            ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle => {
                let ExprSort::BitVec(bits) = arena.sort_of(node.operands[0])? else {
                    return None;
                };
                let left = evaluate(arena, node.operands[0], env)?;
                let right = evaluate(arena, node.operands[1], env)?;
                let holds = match node.op {
                    ExprOp::Ult => left < right,
                    ExprOp::Ule => left <= right,
                    ExprOp::Slt => signed(left, bits) < signed(right, bits),
                    _ => signed(left, bits) <= signed(right, bits),
                };
                Some(u128::from(holds))
            }
            ExprOp::Ite => {
                let condition = evaluate(arena, node.operands[0], env)?;
                if condition != 0 {
                    evaluate(arena, node.operands[1], env)
                } else {
                    evaluate(arena, node.operands[2], env)
                }
            }
            ExprOp::Concat => {
                let ExprSort::BitVec(out_bits) = node.sort else {
                    return None;
                };
                let ExprSort::BitVec(right_bits) = arena.sort_of(node.operands[1])? else {
                    return None;
                };
                let hi = evaluate(arena, node.operands[0], env)?;
                let lo = evaluate(arena, node.operands[1], env)?;
                let value = if right_bits >= 128 { lo } else { (hi << right_bits) | lo };
                Some(value & bit_mask(out_bits))
            }
            ExprOp::Extract => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let immediate: [u8; 4] = node.immediate.as_slice().try_into().ok()?;
                let offset = u16::from_le_bytes([immediate[0], immediate[1]]);
                let value = evaluate(arena, node.operands[0], env)?;
                let extracted = if offset >= 128 {
                    0
                } else {
                    (value >> offset) & bit_mask(bits)
                };
                Some(extracted)
            }
            ExprOp::ZExt | ExprOp::SExt => {
                let ExprSort::BitVec(out_bits) = node.sort else {
                    return None;
                };
                let in_bits = match arena.sort_of(node.operands[0])? {
                    ExprSort::Bool => 1,
                    ExprSort::BitVec(bits) => bits,
                    _ => return None,
                };
                let value = evaluate(arena, node.operands[0], env)?;
                let extended = if node.op == ExprOp::ZExt {
                    value & bit_mask(out_bits)
                } else if in_bits > 0 && in_bits < 128 && value & (1_u128 << (in_bits - 1)) != 0 {
                    (value | !bit_mask(in_bits)) & bit_mask(out_bits)
                } else {
                    value & bit_mask(out_bits)
                };
                Some(extended)
            }
            ExprOp::UDiv | ExprOp::SDiv => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return None;
                };
                let left = evaluate(arena, node.operands[0], env)?;
                let right = evaluate(arena, node.operands[1], env)?;
                if right == 0 {
                    return Some(0);
                }
                let value = if node.op == ExprOp::UDiv {
                    left / right
                } else {
                    (signed(left, bits).checked_div(signed(right, bits)).unwrap_or(0) as u128) & bit_mask(bits)
                };
                Some(value & bit_mask(bits))
            }
        }
    }

    /// Generates a random bitvector expression, deliberately biased toward
    /// the obfuscated shapes this module targets so the differential test
    /// exercises the rewrites, not just the pass-through paths.
    fn gen_bv(
        arena: &ShardedExprArena,
        rng: &mut Rng,
        depth: u32,
        bits: u16,
        next_symbol: &mut u64,
    ) -> Result<ExprId, ExprArenaError> {
        if depth == 0 {
            if rng.below(2) == 0 {
                *next_symbol += 1;
                return symbol(arena, *next_symbol, bits);
            }
            return konst(arena, u128::from(rng.next_u64()), bits);
        }
        let child = |arena: &ShardedExprArena,
                     rng: &mut Rng,
                     at: u16,
                     next_symbol: &mut u64|
         -> Result<ExprId, ExprArenaError> { gen_bv(arena, rng, depth - 1, at, next_symbol) };
        match rng.below(100) {
            0..=14 => {
                let op = [
                    ExprOp::Add,
                    ExprOp::Sub,
                    ExprOp::Mul,
                    ExprOp::And,
                    ExprOp::Or,
                    ExprOp::Xor,
                ][rng.below(6) as usize];
                binary(
                    arena,
                    op,
                    child(arena, rng, bits, next_symbol)?,
                    child(arena, rng, bits, next_symbol)?,
                    bits,
                )
            }
            15..=19 => {
                let x = child(arena, rng, bits, next_symbol)?;
                if rng.below(2) == 0 {
                    unary(arena, ExprOp::Not, x, bits)
                } else {
                    unary(arena, ExprOp::Not, unary(arena, ExprOp::Not, x, bits)?, bits)
                }
            }
            20..=24 => {
                let x = child(arena, rng, bits, next_symbol)?;
                let count_bits = if rng.below(2) == 0 { 8 } else { bits };
                let count = konst(arena, u128::from(rng.below(u64::from(bits) + 3)), count_bits)?;
                let op = [ExprOp::Shl, ExprOp::LShr, ExprOp::AShr, ExprOp::RotL, ExprOp::RotR][rng.below(5) as usize];
                binary(arena, op, x, count, bits)
            }
            25..=29 => {
                let (x, y) = (
                    child(arena, rng, bits, next_symbol)?,
                    child(arena, rng, bits, next_symbol)?,
                );
                let or = binary(arena, ExprOp::Or, x, y, bits)?;
                let and = binary(arena, ExprOp::And, x, y, bits)?;
                if rng.below(2) == 0 {
                    binary(arena, ExprOp::Add, or, and, bits)
                } else {
                    binary(arena, ExprOp::Sub, or, and, bits)
                }
            }
            30..=34 => {
                let x = child(arena, rng, bits, next_symbol)?;
                let inner = binary(
                    arena,
                    ExprOp::Xor,
                    x,
                    konst(arena, u128::from(rng.next_u64()), bits)?,
                    bits,
                )?;
                binary(
                    arena,
                    ExprOp::Xor,
                    inner,
                    konst(arena, u128::from(rng.next_u64()), bits)?,
                    bits,
                )
            }
            35..=39 => {
                let x = child(arena, rng, bits, next_symbol)?;
                let (c1, c2) = (
                    konst(arena, u128::from(rng.next_u64()), bits)?,
                    konst(arena, u128::from(rng.next_u64()), bits)?,
                );
                match rng.below(4) {
                    0 => binary(arena, ExprOp::Add, binary(arena, ExprOp::Add, x, c1, bits)?, c2, bits),
                    1 => binary(arena, ExprOp::Sub, binary(arena, ExprOp::Add, x, c1, bits)?, c2, bits),
                    2 => binary(arena, ExprOp::Sub, c1, binary(arena, ExprOp::Sub, c2, x, bits)?, bits),
                    _ => binary(arena, ExprOp::Add, binary(arena, ExprOp::Sub, c1, x, bits)?, c2, bits),
                }
            }
            40..=44 => {
                if bits > 4 && rng.below(2) == 0 {
                    // Two-level extension a -> b -> bits.
                    let a = 1 + rng.below(u64::from(bits) - 3) as u16;
                    let b = a + 1 + rng.below(u64::from(bits) - u64::from(a) - 2) as u16;
                    let x = child(arena, rng, a, next_symbol)?;
                    let mid = extension(arena, if rng.below(2) == 0 { ExprOp::ZExt } else { ExprOp::SExt }, x, b)?;
                    extension(
                        arena,
                        if rng.below(2) == 0 { ExprOp::ZExt } else { ExprOp::SExt },
                        mid,
                        bits,
                    )
                } else {
                    let narrow = 1 + rng.below(u64::from(bits) - 1) as u16;
                    let x = child(arena, rng, narrow, next_symbol)?;
                    let wide = extension(
                        arena,
                        if rng.below(2) == 0 { ExprOp::ZExt } else { ExprOp::SExt },
                        x,
                        bits,
                    )?;
                    if rng.below(2) == 0 {
                        binary(
                            arena,
                            ExprOp::Add,
                            binary(
                                arena,
                                ExprOp::Add,
                                wide,
                                konst(arena, u128::from(rng.next_u64()), bits)?,
                                bits,
                            )?,
                            konst(arena, u128::from(rng.next_u64()), bits)?,
                            bits,
                        )
                    } else {
                        Ok(wide)
                    }
                }
            }
            45..=49 => {
                let (t, f) = (
                    child(arena, rng, bits, next_symbol)?,
                    child(arena, rng, bits, next_symbol)?,
                );
                let condition = arena.intern(ExprNode {
                    sort: ExprSort::Bool,
                    op: if rng.below(2) == 0 { ExprOp::Eq } else { ExprOp::Ult },
                    operands: vec![
                        child(arena, rng, bits, next_symbol)?,
                        child(arena, rng, bits, next_symbol)?,
                    ],
                    immediate: Vec::new(),
                })?;
                arena.intern(ExprNode {
                    sort: ExprSort::BitVec(bits),
                    op: ExprOp::Ite,
                    operands: vec![condition, t, f],
                    immediate: Vec::new(),
                })
            }
            50..=54 => {
                if rng.below(2) == 0 {
                    let extra = rng.below(33);
                    let in_bits = bits + extra as u16;
                    let offset = rng.below(extra + 1) as u16;
                    let value = child(arena, rng, in_bits, next_symbol)?;
                    arena.intern(ExprNode {
                        sort: ExprSort::BitVec(bits),
                        op: ExprOp::Extract,
                        operands: vec![value],
                        immediate: offset
                            .to_le_bytes()
                            .iter()
                            .copied()
                            .chain(bits.to_le_bytes().iter().copied())
                            .collect(),
                    })
                } else {
                    let left_bits = 1 + rng.below(u64::from(bits) - 1) as u16;
                    let right_bits = bits - left_bits;
                    let hi = child(arena, rng, left_bits, next_symbol)?;
                    let lo = child(arena, rng, right_bits, next_symbol)?;
                    arena.intern(ExprNode {
                        sort: ExprSort::BitVec(bits),
                        op: ExprOp::Concat,
                        operands: vec![hi, lo],
                        immediate: Vec::new(),
                    })
                }
            }
            55..=59 => {
                // x + ~x in either spelling.
                let x = child(arena, rng, bits, next_symbol)?;
                if rng.below(2) == 0 {
                    let not_x = unary(arena, ExprOp::Not, x, bits)?;
                    binary(arena, ExprOp::Add, x, not_x, bits)
                } else {
                    let neg = binary(arena, ExprOp::Sub, konst(arena, bit_mask(bits), bits)?, x, bits)?;
                    binary(arena, ExprOp::Add, neg, x, bits)
                }
            }
            _ => {
                if rng.below(2) == 0 {
                    *next_symbol += 1;
                    symbol(arena, *next_symbol, bits)
                } else {
                    konst(arena, u128::from(rng.next_u64()), bits)
                }
            }
        }
    }

    #[test]
    fn differential_random_trees_preserve_semantics() -> Result<(), ExprArenaError> {
        let mut rng = Rng::new(0x0B1E_5EED_1DEA);
        let arena = arena();
        for tree in 0..200 {
            let bits = [8_u16, 16, 32, 64][rng.below(4) as usize];
            let mut next_symbol = u64::try_from(tree).unwrap_or(0);
            let root = gen_bv(&arena, &mut rng, 4, bits, &mut next_symbol)?;
            let simplified = deobfuscate(&arena, root);

            // Sorts must survive simplification.
            assert_eq!(arena.sort_of(root), arena.sort_of(simplified));

            let mut symbols = Vec::new();
            let mut walk = vec![root];
            while let Some(id) = walk.pop() {
                if let Some(node) = arena.get(id) {
                    if node.op == ExprOp::Symbol {
                        let bytes: [u8; 8] = node
                            .immediate
                            .as_slice()
                            .try_into()
                            .map_err(|_| ExprArenaError::InvalidImmediate)?;
                        symbols.push((u64::from_le_bytes(bytes), node.sort));
                    }
                    walk.extend(node.operands.iter().copied());
                }
            }
            for _ in 0..3 {
                let mut env = FxHashMap::default();
                for &(source, sort) in &symbols {
                    let ExprSort::BitVec(width) = sort else {
                        continue;
                    };
                    env.insert(source, u128::from(rng.next_u64()) & bit_mask(width));
                }
                let before = evaluate(&arena, root, &env);
                let after = evaluate(&arena, simplified, &env);
                assert!(before.is_some(), "evaluator gap on tree {tree}");
                assert_eq!(before, after, "value changed after simplification on tree {tree}");
            }

            // The fixpoint must be stable: simplifying again is a no-op.
            assert_eq!(
                deobfuscate(&arena, simplified),
                simplified,
                "unstable fixpoint on tree {tree}"
            );
        }
        Ok(())
    }
}
