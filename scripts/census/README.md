# Census analysis suite (Lua 5.4, host-side)

Consumes Angryier bulk-census JSONL (one record per probed function) and the
METHRA `index.tsv`. No engine required — plain `lua5.4`. All scripts take a
results JSONL as the first argument; they compose via pipes and jq/pandas.

| Script | Purpose |
|---|---|
| `census_json.lua` | shared field extractor (dofile it; `cj.hex` handles the Lua 5.4 `0x` gotcha) |
| `census_summary.lua` | totals, classification (sentinel/image/section12/low/timeout/error), top exit targets with enclosing names |
| `census_xref.lua` | reverse xref: every entry exiting AT an address/range — the managed-boundary map (`--to 0x1437f3000-0x14bf4d000` = all native callers of section-12 handlers) |
| `census_join.lua` | join census × METHRA index → queryable TSV (SQLite/pandas ready) |
| `census_sentinels.lua` | cluster normal-return functions by rax constant (function families) |

## Examples (ready for the full census)

```sh
# who reaches the generated (section-12) handler stubs?
lua5.4 census_xref.lua results.jsonl --to 0x1437f3000-0x14bf4d000 --index index.tsv > managed_boundary.tsv

# one-line overview
lua5.4 census_summary.lua results.jsonl index.tsv

# evidence base for queries
lua5.4 census_join.lua results.jsonl index.tsv census.tsv
```

The classification ranges in `census_summary.lua` are advisory — edit the
`ranges` table for other targets (oleaut32 stubs, the dispatcher area, etc.).
