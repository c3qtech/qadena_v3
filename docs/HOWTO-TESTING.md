# Testing Qadena

How to build a chain, run the regression suite, and write test cases that actually test something.

Written from mistakes. Nearly every rule here cost a ~20 minute rebuild-and-run cycle to learn, so
the reasoning is included — a rule you understand you can apply to a new situation, a rule you only
memorised you will misapply.

---

## 1. The map

| thing | where |
|---|---|
| chain source | `x/qadena/`, `app/` |
| enclave source | `cmd/qadenad_enclave/` |
| consensus-safe policy shared by both | `x/qadena/common/*_policy.go` |
| genesis input | `config/config.yml` |
| test scripts | `testscripts/` |
| the runner | `testscripts/regression.sh` |
| installed binaries | `$qadenabin` = `$QADENAHOME/bin` |
| chain data, keyring, sealed enclave params | `$QADENAHOME` (default `~/qadena`) |
| chain log | `$QADENAHOME/logs/qadena.log` |
| per-suite logs | `logs/regression/<suite>.log` |

Always `source scripts/setup_env.sh` first. It exports `$qadenabin`, `$QADENAHOME`,
`$qadenatestscripts`, `$minimum_gas_prices`, `$gas_auto`, `$gas_adjustment`, and defines
`increment_id` / `increment_version`.

---

## 2. Running the regression

```sh
./testscripts/regression.sh                        # repeatable suites, against a running chain
./testscripts/regression.sh --from-genesis         # DESTRUCTIVE: wipe and rebuild everything
./testscripts/regression.sh --with-enclave-upgrade # also swap the enclave to a new measurement, last
./testscripts/regression.sh --stop-on-fail
```

`--from-genesis` deletes `$QADENAHOME` outright — chain data **and the keyring** — and rebuilds from
`config/config.yml`. It implies `--with-setup` and `--with-credentials`. Takes ~20 minutes. It is
the only run that proves genesis construction, so it is the run that counts before publishing.

Run it in the background and watch for failures rather than polling:

```sh
./testscripts/regression.sh --from-genesis > /tmp/reg.log 2>&1 &
tail -f /tmp/reg.log | grep -E "^FAIL |ALL [0-9]+ SUITES|SUITES FAILED|FAILED: "
```

### One root cause, many red suites

A failure in `prerequisites` or `setup` cascades: every later suite reports `al not in the keyring`
or `not funded`. **Read the first failure only.** Fifteen red suites are usually one bug.

---

## 3. Building, and the one thing that will wedge your node

`buildscripts/build.sh` **installs** — it calls `install.sh --chain` and then builds the enclave and
signer enclave. `init.sh` calls `build.sh`.

> **Stop the chain before building.** Overwriting `$qadenabin/qadenad` under a running process leaves
> the node serving RPC from resident pages while newly-faulted code paths wedge. The symptom is
> baffling: the chain reports healthy and advancing, `query` hangs, and even a purely local
> `keys show` hangs, because fresh CLI processes exec a binary that was rewritten under them.

`regression.sh --from-genesis` stops the chain itself. If you build by hand, run
`scripts/stop_qadena.sh` first.

Building only the enclave: `buildscripts/build_enclave.sh`. It also rewrites `enclaveIdentityList`
in `$QADENAHOME/config/genesis.json` with the built ids.

> **Never pass `--build-reproducible` with uncommitted work.** That path runs
> `git checkout -f && git clean -fd`.

---

## 4. Init from genesis, by hand

```sh
scripts/stop_qadena.sh
buildscripts/init.sh --advertise-ip-address <ip>   # or omit; regression derives it
scripts/start_qadena.sh
```

`init.sh` copies `config/config.yml` → `config.yml` verbatim, runs `ignite chain init`, then
substitutes placeholders **in the generated genesis.json** with `setPubKAndPubKID.sh` — a plain
`sed`, so `treasuryPubKID` anywhere in the file becomes the real address. Add a new genesis entry
that references a key by placeholder and it just works; `genesis-check` fails the run if any
`*PubKID` survives.

### A reachable chain is not a ready one

`scripts/start_qadena.sh` returns once blocks are produced, but the enclave is initialised by
`delayed_init_enclave.sh`, which waits for **height ≥ 4**. Until `InitEnclave` runs there is no jar
regulator, and every AML-scanned send is refused. Anything that transacts must wait for:

```sh
qadenad query qadena list-jar-regulator --output json | jq -r '.jarRegulator | length'   # > 0
```

`regression.sh`'s `chain-start` and `setup_prerequisites.sh` both do this. Copy it if you write
another entry point.

---

## 5. Writing test cases

### 5.1 The CLI exits 0 on a rejected bank send

The AML scan is skipped in CheckTx, so a doomed transaction still broadcasts, gets a hash, and fails
**inside the block**. The CLI exits 0 and prints a normal-looking JSON response.

**Never assert on the CLI exit code.** Query the transaction result:

```sh
out=$(qadenad tx bank send "$from" "$to" "$amt" --from "$from" --yes --output json "${gas_flags[@]}" 2>/dev/null)
hash=$(echo "$out" | jq -r '.txhash')
qadenad query wait-tx "$hash" --timeout 60s > /dev/null 2>&1 || true
code=$(qadenad query tx "$hash" --output json 2>/dev/null | jq -r '.code // "UNKNOWN"')
```

A `transfer-funds` rejection *is* caught by `--gas auto` simulation, so that path fails at the CLI.
The two behave differently; do not copy an assertion from one to the other.

### 5.2 `2>&1` will break your JSON

`--gas auto` writes `gas estimate: N` to **stderr**. Fold that into captured output and the first
line is not JSON, so `jq -r .code` fails — on a transaction that **succeeded**. You then report a
broken chain when nothing is wrong.

- parsing JSON → capture stdout only (`2>/dev/null`), and if you need stderr for diagnostics,
  redirect it to a temp file
- grepping for an error message → `2>&1` is correct, because rpc errors arrive on stderr

### 5.3 Measure the recipient, not the sender

A refused send still lands in a block and still costs the sender gas, so the sender's balance moves
either way. Asserting `sender_before == sender_after` fails a *correct* refusal — and would pass a
send that went through for less than the fee. Always measure the recipient.

### 5.4 Know your JSON shapes

- `list-suspicious-transaction` returns **`.SuspiciousTransaction`** — capital S. `.suspiciousTransaction`
  yields `null`, and `null | length` is **`0`** in jq, so a wrong key silently reads as "no reports"
  instead of erroring. This is the most dangerous shape mistake in this repo.
- proto `int64` params are JSON **strings**: `"10000"`, not `10000`. `uint32` are numbers.
- `query gov proposal N` nests under `.proposal`.
- `show-wallet` prints `err ... not found` and still **exits 0**. Check the output text, not `$?`.

Verify a shape against a live chain before writing the assertion. It costs one command.

### 5.5 zsh traps

- **`status` is read-only** (it mirrors `$?`). `local status=...` is a fatal error that can tear the
  shell down *without running EXIT traps*. Use `prop_status`, `id_status`, anything else.
- **`[[ ]]` does not expand globs**, quoted or not. `[[ -f "$dir/pre_*.json" ]]` tests a literal
  filename containing an asterisk and is always false. Use `files=($dir/pre_*.json(N)); (( ${#files} ))`.
- **`fail()` must write to stderr.** A helper called inside `$( )` has its stdout captured, so a
  failure message written there vanishes into the variable and `set -e` kills the script with *no
  output at all*.
- zsh parses compound commands as a unit, so a syntax error inside a large `if` block only surfaces
  when execution reaches it. `zsh -n script.sh` before every run.

### 5.6 Assert the mechanism, not just the outcome

- Distinguish error codes. `1159` (unscannable party) and `1162` (whitelisted contract's code was
  migrated) mean different things; asserting only "it failed" would let one masquerade as the other
  and hide the attack the check exists for.
- Where the code travels differs. Errors raised **in the enclave** arrive as gRPC text containing
  `codespace qadena code NNNN`, so grep the raw log. Errors raised **chain-side** by `errorsmod.Wrapf`
  put the number in the transaction's ABCI `code` and only the description in the log — grep for the
  number there and you will never find it.
- Pair a permission with its refusal. "A listed sender may pay an identity-less address" is only
  meaningful next to "an ordinary wallet may not" — otherwise the test passes just as well if the
  check was removed entirely.
- Never let a success assertion stand alone when a silent no-op would satisfy it. "The transfer was
  accepted" also passes if the threshold stopped being applied; assert a report was filed too.

### 5.7 Baselines must be taken late

Take a counter baseline immediately before the action, not at preflight. Setup steps in between
(topping up an account from the treasury is itself a reportable bank send) can satisfy your
assertion on their own, and the case then passes while testing nothing.

### 5.8 Idempotency

Every suite except `credentials` and `enclave-upgrade` must be safe to re-run against the same chain:
delta assertions rather than absolute balances; per-run unique ids **and** content (a DSVS document
is keyed by content hash, so a unique id alone is not enough); fresh deploys for wasm/evm; top up
only when short; guard on end state rather than "have I run before".

If a suite mutates something durable, put it last and behind a flag.

### 5.9 Never skip silently

If a case cannot run, **fail loudly**. A skip that reports success leaves a guard untested while
looking green. If a test depends on something optional, assert the dependency exists.

---

## 6. Governance proposals in tests

- **Deposit** must clear `min_initial_deposit_ratio` (0.25) of the *expedited* minimum. With
  `expedited_min_deposit` 50000qdn that is **12500qdn** at submission; the templates use 100000qdn.
  A `1qdn` deposit fails with `minimum deposit is too small`.
- **Gas flags are required**: `--gas-prices $minimum_gas_prices --gas $gas_auto --gas-adjustment
  $gas_adjustment`. Without them you get `gas prices too low, got: 0`.
- **Expedited proposals convert.** Gov v1 turns an expedited proposal that misses its 30s tally into
  a regular one with the full 300s period — votes carry over, so it still passes, just later. Budget
  waits for the **regular** period or your test is a coin flip.
- **`ValidateBasic` runs at submission.** Gov calls it on every message before creating the proposal,
  and `MsgUpdateParams.ValidateBasic` calls `Params.Validate()`. Invalid params are therefore refused
  when the proposal is *submitted* — no proposal, no deposit, no voting period. Do not expect
  `PROPOSAL_STATUS_FAILED`.
- A **passed** proposal is not an **applied** one. If a message errors during execution the proposal
  ends `PROPOSAL_STATUS_FAILED`. Always verify the resulting state, not the status alone.

---

## 7. Enclave rules

### 7.1 Consensus safety

Code under `cmd/qadenad_enclave/` and `x/qadena/common/*_policy.go` runs on **every validator** and
its verdict decides whether a transaction is accepted. A disagreement between two nodes is a chain
halt, not a bad UX. Therefore:

- **Never range a Go map** where order affects output. Map iteration order is randomised per process.
  This bit us: reports filed in map order got sequential IDs at EndBlock, so two honest nodes
  committed different `(id → report)` mappings and the app hash diverged. Return sorted slices from
  helpers so callers *cannot* make this mistake.
- **No floating point.** Integer comparisons only — `dist*100 <= pct*runeLen`, never `dist/len <= pct/100`.
- **No wall clock.** Block time is passed in.
- **No `golang.org/x/text`.** Its Unicode tables are module-versioned; the stdlib's move only with
  the toolchain.
- **Runes, not bytes** — or `ñ` counts as two edits.

### 7.2 State must be transactional

The enclave's KV cache is rolled back by `TransactionComplete(success=false)`. Anything you add
*outside* that cache is not. Buffer per-transaction state and promote it only on success, or a
failed transaction leaves evidence of something that never happened.

### 7.3 Sealing, and the upgrade rule

Sealing mirrors SGX. In test mode it is a prefix:

| function | prefix | SGX analogue | survives a new enclave build? |
|---|---|---|---|
| `SealWithProductKey` (used by `MustSeal`) | `signerID` | MRSIGNER | **yes** |
| `SealWithUniqueKey` | `uniqueID` | MRENCLAVE | no |

> **Bump the unique id, never the signer id, when upgrading.** Most state is sealed with the product
> (signer) key precisely so a new *measurement* by the same signer can still read it — that is the
> entire upgrade mechanism. Change the signer too and the new enclave unseals nothing: every scan
> dies with `Couldn't unseal, unrecognized prefix` → `ErrGenericScan` (1125), while the chain keeps
> producing blocks and looks healthy.
>
> `build.sh --update-test-unique-id` bumps **both**. It is fine for a fresh chain and wrong for an
> upgrade.

Reports still decrypt after a botched upgrade, because they are encrypted to the regulator's *public*
key rather than sealed — so "old reports are readable" is **not** sufficient evidence that an upgrade
worked. Prove the sealed store survived by making a real scanned send.

### 7.4 The upgrade sequence

1. Register the next identity by governance, status `unvalidated`
   (`testscripts/test_update_enclave_identity.sh <uniqueid> <signerid> unvalidated`).
2. Wait for it to become **`active`** — the old enclave refuses to hand its keys to a non-active
   identity (`couldn't find an active enclave identity for uniqueID: ...`). Promotion happens in
   `validateEnclaveIdentities()`, whose only trigger is a counter that fires on the first proposer
   `UpdateHeight` **after the enclave process starts**, then not again for ~555 × 11 ≈ 6100 blocks.
   In practice: restart the node to force the window.
3. Stop the chain, `build_enclave.sh`, start the chain. `run.sh` runs `check_upgrade_enclave.sh`
   *before* launching anything; `upgrade_enclave.sh` boots the **old** enclave in `--upgrade-mode` so
   the new one can dial it on 50051 and pull the keys across. There is no hot-upgrade path.
4. Verify: `enclave_params_<new>.json` exists, its `RegulatorPrivK` and `JarPrivK` **byte-match** the
   old ones, old reports still decrypt, **and a scanned send still works**.

`testscripts/test_enclave_upgrade.sh` does all of this; read it before changing the upgrade path.

---

## 8. Debugging

```sh
# what actually refused a transaction (enclave errors land here, not in the tx log)
grep -aiE "refusing|scannable|unrecognized prefix|couldn't find" $QADENAHOME/logs/qadena.log | tail -20

# the upgrade decision
grep -aE "Found enclave type|Main enclave version|Initiating upgrade|Upgrade successful|no upgrade" \
    $QADENAHOME/logs/qadena.log | tail
```

Beware: hex app hashes contain digit strings, so `grep 1159` matches `...CFD741159A38...`. Grep for
the message text, not the bare number.

Previous sessions' transcripts are under
`~/.claude/projects/<encoded-path>/*.jsonl` — useful for recovering what was in flight after a crash.

---

## 9. Before you say it works

- `zsh -n` every script you touched.
- `go build ./x/... ./app/... ./cmd/qadenad_enclave/...` — `go build ./...` fails on the `ego`
  enclave client unless the EGo toolchain is installed, which is expected and unrelated.
- `go test ./x/qadena/common/... ./x/qadena/types/...` — note `TestAddress` in `common_test.go`
  fails independently of your change; confirm with `git stash` before blaming yourself.
- Full `--from-genesis` run, green, in **one** sequence. Individually-passing suites are not the
  same claim.
- Report the summary as it is. If a suite failed, say so and say why.
