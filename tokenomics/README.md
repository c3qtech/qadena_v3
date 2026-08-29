# tokenomics/

Everything the QDN token launch is built from. `qadena-master-brief.md` is authoritative; this
README says what is here, what has been verified, and what is still open.

## Contents

| file | status |
|---|---|
| `qadena-master-brief.md` | **The brief — one document, read this.** All-native custody on core SDK only. Economics, Phase A results, Phases B–D, runbooks, hard rules, open questions. |
| `allocations.csv` | **Human-owned.** Never edited by tooling. A missing value stops work and asks. |
| `gating-findings.md` | Phase A results, with pasted output. |

Phase B deliverables (`build_genesis.py`, `verify_genesis.py`, `export_unlock_schedule.py`) are
**not here yet** — Phase A gates them, and one open question below blocks Phase B specifically.

## allocations.csv

Ten buckets plus one genesis-validator row. `bucket_id` **08 and 11 are intentionally absent** —
ten buckets, not twelve. Rows sharing a `bucket_id` are one bucket: Node Operations is a reserve
row plus the genesis validator row, and its percentage is per-bucket while token counts are
per-row.

Addresses are placeholders (`<NN_MSIG_ADDR>`, `<GENVAL_1_ADDR>`). Verify assertion 13 must reject
them on a mainnet build; they are allowed in dev builds behind a flag.

The CSV already satisfies brief assertions 1–4, checked directly:

```
rows: 11 | distinct buckets: 10 | pct sum: 100
total tokens_qdn: 4,000,000,000
total aqdn:       4000000000000000000000000000
every bucket: row sum == 4_000_000_000 * pct // 100    OK
```

Reproduce with the snippet in `gating-findings.md` §CSV arithmetic.

## Conventions

- `tokens_qdn` is whole QDN. Convert **once** at load: `aqdn = qdn * 10**18`.
- Integer arithmetic only. No floats anywhere near amounts.
- Every JSON amount is a string.
- `qdn` is a display denom and must never appear in an on-chain amount.
- Never generate or commit real keys or mnemonics.

## A note on this copy of the brief

The source document arrived with UTF-8 punctuation transcoded (em-dashes and middle dots showing
as `â` / `Â·`). This copy restores the intended characters. **No wording, number, rule or heading
was changed.** ASCII arrows (`->`) in the original are left as ASCII.

## Test results

**Phase A (A1–A8), the original CosmWasm design: 4 PASS, 3 FAIL, 1 NOT-EXERCISED — it does not pass.**
A1 and A3 fail because the released cw-plus binaries compile `cosmwasm-std` with no features, so
`CosmosMsg::Any` and `CosmosMsg::Staking` do not exist in them. A2 fails because a native multisig
cannot spend without an AML whitelist entry.

**Native custody (N1–N6): 5 PASS, 1 NOT-EXERCISED, 0 failures.** Locked principal delegates;
unbonding returns it still locked; rewards are liquid; a multisig threshold can grant authz to an
operator who needs no eKYC and no whitelist; a `StakeAuthorization` holder can delegate but not
spend.

**Conclusion: the native design does everything the token model needs, and the contract design does
not.** See `qadena-master-brief.md` §4 for the tested capability list and the limits.

## Where the chain disagrees with the brief

Conflicts found by testing rather than reading. All are recorded in full in
`gating-findings.md`; in short:

1. **HARD RULE 7 (`qadena-dev-*` chain-ids) is unusable on this chain.** The EVM chain ID is
   derived by *parsing* the Cosmos chain-id (`cmd/qadenad/cmd/commands.go`), which requires
   `<name>_<number>-<number>`. A chain-id with no `_` fails that parse **silently** and leaves the
   EVM on a fallback ID. Chain-ids are assigned in `config/launch-config.yml` instead.

2. **The 11-account genesis is incompatible with `x/qadena`'s own genesis requirements** — it is
   name-bound to `pioneer1` and `treasury`. This does not block Phase A. **It blocks Phase B.**

3. **D1's "personal 2-of-3 multisig advised" strands the founder as written.** A native multisig
   holds no eKYC credential, so it can receive a grant but cannot spend — refused with code 1159,
   and it pays the fee to fail. Verified fix: a governance whitelist entry naming the address with
   `codeID: 0`. That is per-address governance work on the critical path of every large grant.

4. **`cw-vesting` is not in cw-plus**, and ships in two builds. Foundation (504M, delegated while
   locked) needs `-staking`; Long-Term Reserve needs `-no_staking`. The brief says only
   "cw-vesting", which is not specific enough to deploy from.

## Reproducing the tests

```sh
./testscripts/regression.sh --from-genesis   # build the devnet (DESTRUCTIVE, ~20 min, 25 suites)

./testscripts/fetch_token_contracts.sh       # download + checksum-verify the cw artifacts
./testscripts/test_token_gating.sh           # A1-A8, the original CosmWasm design

./testscripts/test_native_custody.sh         # N1-N6, the native design
```

Evidence lands in `logs/token-gating/` and `logs/native-custody/` — one `*.tx.json` per transaction,
plus `environment.txt` and `summary.txt`. Every verdict in the findings quotes those files.

`test_native_custody.sh` N3 needs a short `unbonding_time`; the devnet's 21 days was reduced to 120s
by governance for the recorded run. Without that, N3 correctly reports NOT-EXERCISED.

**Read `gating-findings.md` §12 before writing anything against this chain.** It lists eight traps
that produce plausible-but-wrong output rather than obvious failures — the AML scan being skipped in
simulation (so a refused tx exits 0), zsh's read-only `status`/`GID`, `2>&1` folding `gas estimate:`
into JSON, and the legacy amino account shape among them.
