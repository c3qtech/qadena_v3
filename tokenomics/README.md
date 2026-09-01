# tokenomics/

Everything the QDN token launch is built from. `qadena-master-brief.md` is authoritative; this
README says what is here, what has been verified, and what is still open.

---

## Quickstart

**Check the allocations add up** (no chain, no genesis, takes a second):

```sh
./verify_genesis.py --csv-only --allow-placeholders
```

**Build a dev genesis and verify it:**

```sh
./measure_block_time.sh                       # against a running chain -> block time

qadenad init dev --chain-id qadena_4828-1 --home /tmp/g

./build_genesis.py --base /tmp/g/config/genesis.json \
                   --chain-id qadena_4828-1 --block-time 1.467 \
                   --out /tmp/g/config/genesis.json \
                   --allow-placeholders --verify
```

### Where `blocks_per_year` comes from — measure it, do not copy it

`blocks_per_year = 31,536,000 / seconds-per-block`, and the brief requires the block time to be
**measured**. Do not read it off `timeout_commit`: that is a *floor*, not a rate.

x/mint pays `annual_provisions / blocks_per_year` on **every block**. Set it below the true rate and
each block pays too much *and* there are more blocks than assumed — the error compounds twice,
silently, for the life of the chain.

| source | s/block | blocks_per_year |
|---|---|---|
| devnet `timeout_commit` (a target) | 1.5 | 21,024,000 |
| **measured**, Phase A | 1.467 | 21,496,932 |
| **measured**, later run | 1.564 | 20,159,824 |
| mainnet target, unmeasured | 3.0 | 10,512,000 |

The devnet's *configured* 21,024,000 against a measured 1.467s is ~2% of over-mint — a "1%"
inflation really paying 1.02%. And the two measurements differ by 7%, so **sample over minutes**;
`build_genesis.py` warns if the value you pass implies exactly 1.5s or 3.0s, because those are
targets rather than observations.

**Regenerate the unlock schedule:**

```sh
./export_unlock_schedule.py --summary
```

**Check a genesis you have already built:**

```sh
./verify_genesis.py --genesis /tmp/g/config/genesis.json --allow-placeholders --pre-gentx
```

> Do **not** point this at a running devnet's `~/qadena/config/genesis.json` and expect a pass.
> That genesis comes from `config/config.yml` and holds `pioneer1` + `treasury` = 2.001B QDN, not
> the ten buckets — so it fails assertion 4 with `balances sum to 2001000000000000000000000000,
> expected 4000000000000000000000000000`. That is the verifier being right, not broken. This tool
> checks **token-launch** genesis files.

Every script takes `--help`. `verify_genesis.py` exits **non-zero on the first failure**, naming
the bucket, so it drops straight into CI or a pre-flight check.

Three things that will bite you if you skip them:

| | |
|---|---|
| `--allow-placeholders` | Needed until the ten real `<NN_MSIG_ADDR>` values exist. A mainnet build must **not** pass it. |
| `--pre-gentx` | Needed before `collect-gentxs`. `build_genesis.py` passes it automatically when verifying its own output. |
| `qadenad genesis validate` | **Not** `qadenad validate-genesis` — the older form exits "unknown command" on this SDK. |

Detail for all of it is under [Building a genesis](#building-a-genesis).

---

## Contents

| file | status |
|---|---|
| `qadena-master-brief.md` | **The brief — one document, read this.** All-native custody on core SDK only. Economics, Phase A results, Phases B–D, runbooks, hard rules, open questions. |
| `allocations.csv` | **Human-owned.** Never edited by tooling. A missing value stops work and asks. |
| `gating-findings.md` | Phase A results, with pasted output. |
| `verify_genesis.py` | 16 assertions. Exits non-zero on the FIRST failure, naming the bucket. |
| `build_genesis.py` | CSV -> genesis.json. Deterministic; patches a real `qadenad init` skeleton. |
| `export_unlock_schedule.py` | Monthly unlock / circulating / minted-supply table, TGE to month 120. |
| `measure_block_time.sh` | Samples a running chain for `--block-time`. |
| `unlock_schedule.csv` | Generated. Do not edit. |

Phase B's three tools are built and tested. What is **not** done: the ten real bucket addresses,
which is why every command above carries `--allow-placeholders`, and the open questions below.

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

## Building a genesis

```sh
# 1. render the ignite config from launch-config.yml + allocations.csv
#    NOTE: it must land at config/config.yml -- see the warning below
./build_config.py --out ../config/config.yml

# 2. ignite builds genesis.json from it
buildscripts/init.sh

# 3. check the artifact (pre-gentx: no validator collected yet)
./verify_genesis.py --genesis $QADENAHOME/config/genesis.json --pre-gentx

# 4. gentx, collect, then verify IN FULL -- assertion 12 runs this time
qadenad genesis gentx ... && qadenad genesis collect-gentxs --home $QADENAHOME
./verify_genesis.py --genesis $QADENAHOME/config/genesis.json --expect-evm-id 482

# 5. the chain's own check
qadenad genesis validate --home $QADENAHOME
```

### `init.sh` overwrites `config.yml` — render to `config/config.yml`, not the repo root

[`buildscripts/init.sh:148`](../buildscripts/init.sh) does
`cp config/config.yml config.yml` **unconditionally**, so a rendered file left at the repo
root is silently discarded and you get the devnet chain instead of yours. That copy is
deliberate: it used to skip when the generated file "looked complete", which meant edits to
`config/config.yml` had no effect until you remembered to delete the stale copy.

`config/config.yml` is **the devnet's config and is tracked in git**, so rendering over it
replaces the devnet setup. Commit or stash it first — that is what makes the devnet
recoverable. `build_config.py` warns whenever `--out` is anywhere else.

**`qadenad genesis validate`, not `qadenad validate-genesis`.** The brief's older wording
exits "unknown command" on this SDK.

`build_genesis.py` **patches a skeleton rather than fabricating one.** A genesis carries
consensus params and 35 module sections whose shape moves with the SDK; hand-generating
them would be a second, silently-drifting definition of the chain. The script sets only
accounts, balances, supply, denom metadata, mint params, the AML whitelist and the
incentive-pool entry, and passes everything else through.

**Output is deterministic** -- sorted keys, fixed separators -- so the same inputs give a
byte-identical file and the same SHA256. That is what lets a second person reproduce the
hash, which the Definition of Done requires.

### Two flags that exist for real reasons

- `--allow-placeholders` -- permits `<NN_MSIG_ADDR>`. **Dev builds only**; assertion 13
  fails a mainnet build on them. Note that `qadenad genesis validate` rejects a
  placeholder genesis anyway: the addresses are not parseable bech32, so the SDK decodes
  them all to the same value and reports "duplicate account".
- `--pre-gentx` -- skips assertion 12. `qadenad init` produces no gentx, so the artifact
  this script writes is by definition pre-gentx; the validator check belongs after
  `collect-gentxs`.

## The unlock schedule has a known limitation

`export_unlock_schedule.py` implements the brief exactly, and the result is that
**`circulating_qdn` is FLAT at 56,010,100 QDN for all 120 months.**

That is not a bug in the script. 85% of supply sits in buckets marked `circulating=no`,
and nothing in the CSV ever moves a token out of that state. The column describes a
bucket's status *at genesis*, not the destiny of grants issued from it -- a founder grant
that vests and is sold is plainly circulating, while its bucket stays `no`.

So the column answers *"how much is liquid in accounts that are themselves float"* and
**not** *"how much could reach a market"*. The second question needs a payout assumption
per bucket that `allocations.csv` does not carry. **Reported, not invented** (HARD RULE 1)
-- it needs a human decision.

The **unlock** columns are unaffected and meaningful: LTR rises linearly to 600M over 120
months, Foundation reaches 560M at month 72, and the total lands exactly on 4,000,000,000.

TGE circulating computes to 56,010,100 QDN (1.40%), matching the brief's ~56.0M +
validator floats prediction.

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
