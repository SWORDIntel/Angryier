# AI Operator Guide: Driving Angryier Symbolic Execution

This guide outlines procedures, best practices, and non-negotiable safety rules for AI agents orchestrating symbolic execution and solver queries in `Angryier`.

---

## 1. Guiding Philosophy: Formal Verification & Refutation

As an AI operator driving `Angryier`:
1. **Refutation over Proof**: Symbolic execution excels at finding concrete counterexamples (bugs, crashes, reachable sinks). It refutes the hypothesis that a bug does not exist.
2. **Never Hallucinate Reachability**: A path is reachable if and only if the SMT solver returns `SAT` with a concrete, verifiable model.
3. **Never Equate Timeout with Safety**: When a solver query times out or the state budget is exhausted, the result is strictly **INCONCLUSIVE**.

---

## 2. Formulating Bounded Queries Without State Explosion

Symbolic execution naturally suffers from path explosion when encountering unconstrained loops, nested branches, or unconstrained pointers. Operators must formulate bounded queries.

### 2.1 Setting Strict Budgets

Always enforce explicit bounds on exploration depth and state count:

```bash
angryier run <driver.sys> \
  --handler 0x140001000 \
  --find 0x140001520 \
  --avoid 0x140001210,0x140001350 \
  --max-steps 3000 \
  --max-states 32 \
  --timeout 60 \
  --solve
```

#### Key Budget Parameters:
- `--max-steps <N>`: Maximum execution steps per path before pruning (typically $1,000$ to $5,000$).
- `--max-states <N>`: Maximum active states in the exploration worklist (typically $16$ to $64$). Prevents memory exhaustion.
- `--timeout <SEC>`: Overall execution timeout in seconds.
- `--find <VA>`: Target virtual addresses (e.g. vulnerability sinks). Execution records a `found` state upon reaching any of these.
- `--avoid <VA,...>`: Virtual addresses to prune immediately (e.g. error exits, invalid parameter returns, teardown paths). Pruning dead paths frees worker capacity.

### 2.2 Controlling Symbolic Loops
- Unconstrained loops can fork infinite paths ($k=0, 1, 2, \dots$).
- When analyzing loops, configure loop iteration bounds. If an inner loop index is symbolic, constrain the loop trip count ($\le 4$) to verify loop boundary logic without unbounded unrolling.

### 2.3 Resolving Symbolic Pointers (Concretization)
When an instruction dereferences a symbolic address (`mov rax, [rbx]` where `rbx` is symbolic):
- **Avoid Region-Fork Children**: Forking a child state for every valid memory region generates high fidelity debt (`region_fork_children`).
- **Targeted Concretization**: Pin the symbolic address to a deterministic mapped region (e.g., within the synthetic `INPUT_BUFFER_ADDR` `0x0700_0000` or `DEVICE_EXTENSION_ADDR` `0x444e_0000`).

---

## 3. Interpreting SMT Models and Concrete Trigger Values

When a target is reached with `--solve`, `Angryier` invokes the SMT solver to produce a concrete model satisfying all path constraints.

### 3.1 Extracting Concrete Models

The output JSON contains the concrete assignments:

```json
{
  "found": 1,
  "found_pcs": ["0x140001520"],
  "inputs": [
    {
      "ioctl_code": "0x00222004",
      "input_buffer_hex": "41414141ffffffff00000000",
      "registers": {
        "rcx": "0x00000000444d0000",
        "rdx": "0x0000000001337000",
        "r8": "0x00000000ffffffff"
      }
    }
  ]
}
```

### 3.2 Identifying Vulnerability Trigger Values

Inspect model values for classic arithmetic and boundary edge cases:
- **Integer Wrap / Overflow**: `0xFFFFFFFF` (32-bit `UINT_MAX`) or `0xFFFFFFFFFFFFFFFF` (64-bit `UINT64_MAX`).
- **Signed Integer Underflow**: `0x80000000` (`INT_MIN`).
- **Null Pointers & Zero Lengths**: `0x00000000` or length `0` triggering zero-allocation heap flaws.
- **Maximum Buffer Bounds**: Lengths matching allocation boundaries $+ 1$ (off-by-one indicators).

When documenting findings, extract the exact hex buffer payload and explain why the solver selected those bytes (e.g., passing a header magic check `0x41414141` followed by an integer size `0xFFFFFFFF`).

---

## 4. Handling Timeouts and Unknowns Honestly

### 4.1 Outcome Classification Matrix

| Solver Outcome | Meaning | Permissible Interpretation |
| :--- | :--- | :--- |
| `SAT` | Constraints satisfied | Path is **proven reachable**; model is valid witness. |
| `UNSAT` | Constraints contradictory | Path is **proven unreachable** under tested assumptions. |
| `TIMEOUT` | Solver deadline exceeded | **Inconclusive**. Path may or may not be reachable. |
| `UNKNOWN` | Solver gave up (quantifier/theory) | **Inconclusive**. Path cannot be proven either way. |
| `RESOURCE_LIMIT`| Memory/conflict limit hit | **Inconclusive**. Path budget exhausted. |

### 4.2 The Cardinal Honesty Rule

> **CRITICAL RULE**: NEVER report a target as "safe" or "unreachable" because a symbolic execution query timed out or returned `UNKNOWN`.

If an exploration query expires:
1. Report the status as `INCONCLUSIVE_TIMEOUT`.
2. Document the last explored program counter and the unresolved branch predicate.
3. Suggest increasing `--timeout`, adding `--avoid` addresses to prune irrelevant branches, or decomposing the query into smaller sub-paths.

---

## 5. Concolic Execution and Crash Triage Procedures

To eliminate false positives from symbolic execution approximations, `Angryier` supports concrete replay validation (`branch_analysis.replay`).

```
  [SMT Model Extracted]
            │
            ▼
 [Concrete Reset Snapshot]
 (Registers & Input Buffer)
            │
            ▼
[Concrete Dynamic Execution]
            │
    ┌───────┴───────┐
    ▼               ▼
[Target Reached] [Branch Diverged]
  (validated)       (mismatch)
```

### 5.1 Three-Part Dynamic Identity

Every branch candidate is identified by a three-part dynamic tuple:
1. **Branch PC**: Virtual address of the conditional branch instruction.
2. **Visit Index**: 1-based occurrence count of reaching this instruction on the trace (e.g. 3rd iteration of loop).
3. **Trace Fingerprint**: Cryptographic hash of the sequence of basic block addresses from function entry to the branch.

This ensures replay tests the exact dynamic context rather than an arbitrary traversal of the same static branch.

### 5.2 Replay Statuses and Triage Actions

- `validated`: The concrete execution replayed from entry with model inputs reached the exact target PC. **Finding confirmed**.
- `mismatch`: Execution took a different edge at the branch. Indicates missing path constraint or unmodeled memory aliasing.
- `path-context-mismatch`: Reached the branch via an alternate execution route. The concrete inputs altered earlier control flow.
- `ambiguous-model`: The solver model contained conflicting register assignments.
- `budget-exhausted`: Concrete execution exceeded step limits before reaching the branch.
- `terminated-before-branch`: Target crashed or exited early (e.g., due to an unmodeled Windows API returning an error code).

### 5.3 Crash Triage Procedure

When a validated crash or sink reach is observed:
1. **Extract Proof-of-Concept**: Package the concrete input buffer bytes and IOCTL code into a standalone reproduction script (e.g. a Python `DeviceIoControl` wrapper).
2. **Trace Root Cause**: Trace back from the sink address to identify which input bytes influenced the sink arguments (e.g., input buffer offset 8 flows into the size parameter of `MmMapIoSpace`).
3. **Check Remediation**: Verify whether bounds checks exist between the dispatch entry and the sink call.
