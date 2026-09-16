# Bringing up a launch chain (mainnet, and mainnet-parameter testnets)

Companion to [HOWTO-TEST-FLEET-BRINGUP.md](HOWTO-TEST-FLEET-BRINGUP.md), which brings up a **test**
fleet on the devnet's own parameters.  This one brings up a chain built from
`config/launch-config.yml` + `tokenomics/allocations.csv` -- a genesis meant to be permanent.

**It covers a mainnet-parameter TESTNET too**, and that is the point of having one: a rehearsal is
only worth running if it differs from the real thing in ways you can enumerate.  So enumerate them:

| | mainnet | mainnet-parameter testnet |
|---|---|---|
| chain-id | `qadena_482-1` | its own (`qadena_4824-1`) -- never the mainnet id. `--chain-id` |
| governance timings | 72h / 6h | **may be shortened** -- `--test-gov-timings` (300s / 30s / 300s) |
| everything else | — | **identical**: SGX, allocations, buckets, the ceremony, the AML whitelist |

There is **one template**, `config/launch-config.yml`, and both networks render from it. A
testnet is not a second tracked file -- that only creates two things to keep in sync, with nothing
checking that they were. It is the same template plus two flags, so the whole difference between
your testnet and mainnet is readable on one command line:

```sh
foundation_scripts/fill_launch_config.py \
    --apply     ~/launch/addresses.csv \
    --chain-id  qadena_4824-1 \
    --test-gov-timings \
    --out       ~/launch/testnet-launch-config.yml
```

`--chain-id` rewrites BOTH `chain_id` keys (the top-level one and the nested one that must match)
and validates the format first, because `cmd/qadenad/cmd/commands.go` derives the EVM chain id by
parsing that string and **every failure path is a bare `return`** -- a malformed id leaves
`EVMChainID` unset with no error at init, no error at start, and the mismatch surfacing later as
transactions that will not verify.

`--test-gov-timings` **without** `--chain-id` is refused outright: a five-minute voting period on
the mainnet chain-id is a testnet wearing production's identity, and since EIP-155 replay
protection *is* the chain id, anything signed there would replay against mainnet.

Shortened governance is the one difference that stays a rehearsal.  Change more than that -- debug
enclaves, a trimmed bucket set, a treasury seeded at genesis instead of provisioned by ceremony --
and the testnet stops exercising the things most likely to go wrong, which are precisely the ones
this document exists for.  `--test-gov-timings` alters the instance only; quorum, threshold and
deposits are untouched.

Read [../tokenomics/qadena-master-brief.md](../tokenomics/qadena-master-brief.md) first --
it is authoritative for every percentage, token count, cliff and threshold.  This document
is the mechanics, not the design.

---

## Quick start -- TESTNET

Start here if you are rehearsing.  It is the mainnet sequence with **three flags** and **one step
skipped**; everything else is identical on purpose, because a rehearsal is only worth running if it
differs from the real thing in ways you can enumerate.

```sh
# 1. MINT THROWAWAY KEYS.  Same script as mainnet -- rehearsing custody is the point.
#    Keep them somewhere clearly separate from the real ones.
foundation_scripts/derive_launch_keys.sh \
    --home          ~/testnet/coord \
    --mnemonics-dir ~/testnet/mnemonics \
    --out           ~/testnet/addresses.csv

# 2. BACK UP + RESTORE-TEST.  Rehearse this too; a backup nobody has restored is
#    a hypothesis, and finding that out on the testnet is the entire point.
foundation_scripts/backup_mnemonics.sh --dir ~/testnet/mnemonics \
    --out-dir ~/testnet/backup --parts 5 --threshold 3
foundation_scripts/restore_mnemonics.sh --shares ~/testnet/backup --out-dir /tmp/verify
#    RESTORING IS NOT VERIFYING.  Compare, or all you have proven is that the
#    shares reassemble into something tar accepted.
diff -r ~/testnet/mnemonics /tmp/verify && echo "BACKUP VERIFIED" || echo "BACKUP IS BAD"
rm -rf /tmp/verify

# 3. SKIPPED -- DO NOT EDIT tokenomics/allocations.csv.
#    It is TRACKED.  Filling it with throwaway addresses and committing them puts
#    dev keys in the permanent custody record, and nothing downstream would catch it:
#    addresses.csv and allocations.csv would agree, so every assertion passes.
#    --allow-placeholder-allocations in step 5 covers the gap instead.

# 4. RENDER.  --chain-id and --test-gov-timings are the whole difference from mainnet.
foundation_scripts/fill_launch_config.py \
    --apply     ~/testnet/addresses.csv \
    --chain-id  qadena_4824-1 \
    --test-gov-timings \
    --out       ~/testnet/testnet-launch-config.yml

# 5. BUILD.
buildscripts/init.sh \
    --mainnet-source        ~/testnet/testnet-launch-config.yml \
    --advertise-ip-address  <this node's ip> \
    --allow-placeholder-allocations \
    --pioneer-mnemonic-enc  ~/testnet/mnemonics/qfi-pioneer1.mnemonic.enc

# 6. START IT.
./scripts/start_qadena.sh
```

### The three flags, and why each is refused without the others

| flag | what happens without it |
|---|---|
| `--chain-id qadena_4824-1` | step 4 **refuses**: `--test-gov-timings` on the mainnet id is a testnet wearing production's identity, and EIP-155 replay protection *is* the chain id |
| `--test-gov-timings` | governance runs at 72h/6h, so anything gated on a proposal blocks for three days and the fleet suites cannot run unattended |
| `--allow-placeholder-allocations` | step 5 **refuses** at assertion 13, because you skipped step 3 |

There is no separate testnet template.  `config/launch-config.yml` is the single tracked source and
both networks render from it -- a second file would only be two things to keep in sync, with
nothing checking that they were.  (One existed briefly, `config/testnet-launch-config.yml`; it
carried the *mainnet* chain-id, had half-applied timings, and nothing read it.  It was deleted.)

### What this rehearsal does NOT exercise

`--allow-placeholder-allocations` relaxes exactly one thing: it stops requiring real addresses in
`allocations.csv`.  Everything else still runs -- amounts, supply totals, per-bucket sums, mint
params, module accounts, denom metadata, the AML whitelist, the incentive-pool identity.

What it costs you is the **address** comparison: assertions 5, 14 and 15 skip placeholder rows, and
`fill_launch_config --apply`'s cross-check has nothing to compare against.  So a mis-derived bucket
address would not be caught on this path.  That gap closes only on a run where step 3 is done for
real, which is worth doing **once, on the real bucket multisigs, before mainnet** -- it is the only
configuration that tests the custody chain end to end.

---

## Quick start -- MAINNET

The phases below explain WHY each step is shaped the way it is.  This is the order to type them in.
Nothing here is a shortcut past a phase: every command is one a phase documents.

```sh
# 1. MINT THE KEYS.  Encrypted keyring; each mnemonic sealed as it is created, never
#    written in the clear.  Asks for the passphrase once, reuses it for all ~130 keys.
foundation_scripts/derive_launch_keys.sh \
    --home          ~/launch/coord \
    --mnemonics-dir ~/launch/mnemonics \
    --out           ~/launch/addresses.csv

# 2. BACK IT UP BEFORE GOING FURTHER, and test the restore the same day.
#    A backup nobody has restored is a hypothesis.
foundation_scripts/backup_mnemonics.sh --dir ~/launch/mnemonics \
    --out-dir ~/launch/backup --parts 5 --threshold 3
foundation_scripts/restore_mnemonics.sh --shares ~/launch/backup --out-dir /tmp/verify
#    RESTORING IS NOT VERIFYING.  Compare byte for byte, or all you have proven is
#    that the shares reassemble into something tar was willing to unpack.
diff -r ~/launch/mnemonics /tmp/verify && echo "BACKUP VERIFIED" || echo "BACKUP IS BAD"
#    then move the 5 shares to 5 SEPARATE places and delete /tmp/verify
rm -rf /tmp/verify

# 3. FILL tokenomics/allocations.csv BY HAND -- the genesis_address column.
#    Human-owned (HARD RULE 1); no tool writes it.  Mapping in Phase 1 below.
#    init.sh runs this same check before it destroys anything, so this is an early
#    look, not a load-bearing step.  It costs a second; take the early look.
python3 foundation_scripts/verify_genesis.py --csv-only        # must pass with NO placeholders

# 4. RENDER THE INSTANCE.  Addresses substituted, amounts taken from allocations.csv,
#    the validator left for the node's own keyring to mint.  Cross-checks the two CSVs
#    against each other and REFUSES on any disagreement -- see below.
#    Add --test-gov-timings for a testnet.  Keep --out OUTSIDE the repo.
foundation_scripts/fill_launch_config.py --apply ~/launch/addresses.csv \
    --out ~/launch/launch-config.yml

# 5. BUILD.  init.sh opens the sealed mnemonic itself and prompts for the passphrase,
#    so the mnemonic reaches neither a file nor `ps`.  Do NOT pipe `mnemonic.sh show`
#    into it: both sides of a pipeline run at once, and its passphrase prompt collides
#    with init.sh's own output.
buildscripts/init.sh \
    --mainnet-source        ~/launch/launch-config.yml \
    --advertise-ip-address  <this node's public ip> \
    --pioneer-mnemonic-enc  ~/launch/mnemonics/qfi-pioneer1.mnemonic.enc

# 6. START IT.
./scripts/start_qadena.sh
```

### What stops you between those steps

`init.sh --mainnet-source` gates three times, and all three refuse rather than warn:

| gate | when | catches |
|---|---|---|
| `verify_genesis.py --csv-only` | **before** `rm -rf $QADENAHOME` | `allocations.csv` not adding up, or still holding `<NN_MSIG_ADDR>` placeholders -- the human-owned file, checked before anything reads it as authority |
| `verify_launch_config.py --strict` | **before** `rm -rf $QADENAHOME` | an amount disagreeing with `allocations.csv`, anything unset -- while nothing is destroyed yet |
| `verify_genesis.py --pre-gentx` | **after** `ignite chain init` | a genesis that does not say what the CSV says; `ignite` sits between the two, so verifying the input is not verifying the output |

The first gate exists because the second cannot cover for it. `verify_launch_config` compares the
*instance* against the CSV, and the instance gets its addresses from `addresses.csv` -- so a stale
`genesis_address` column is invisible to it. Verified: a rendered instance with all 12 placeholders
still in the CSV reports `LAUNCH-READY, 0 wrong, 0 unset`. Without the CSV gate the only thing that
notices is assertion 13, which fires about 250 lines and one `rm -rf $QADENAHOME` later.

Bypasses exist (`QADENA_SKIP_CONFIG_VERIFY=1` covers both pre-wipe gates, `QADENA_SKIP_GENESIS_VERIFY=1`
the last) and announce that amounts are unverified.

**`--allow-placeholder-allocations`** is a different thing and not a bypass: it permits
placeholder addresses in `allocations.csv` while still running every other assertion. A
launch-**shaped** test build needs it -- the real bucket multisigs do not exist until the real
launch, so the tracked CSV holds placeholders and is right to. `testscripts/1st_node_bringup.sh`
passes it for you on `--mainnet-source`. **A real launch never passes it**, which is the whole
point of assertion 13.

It is a **flag rather than an environment variable** deliberately. An env var is ambient -- set in
a `.zshrc`, a CI job or a parent shell, it would silently disable assertion 13 on a real launch
build with nothing in the reviewed command to show for it. A flag can only be set by the caller,
appears in `ps` and in the run log, and is listed by `init.sh --help`. The `QADENA_SKIP_*`
variables stay variables because they are "I know I am disabling verification" escape hatches;
this is a routine mode for an entire class of build, and routine things belong in the interface.

> **NOT YET EXERCISED END TO END.**  Steps 3-5 have not been run as a chain: `--apply` began
> applying amounts on 2026-09-04 and neither `init.sh` gate has fired on a real build.  Do it once
> on a throwaway chain before doing it on one whose genesis is permanent.

---

## The principle

**A private key belongs on the machine that must use it, and nowhere else.**

That is not the same as "no keys on the build host".  Which host may hold what depends on
who is building:

| | who builds genesis | may the validator key be there? |
|---|---|---|
| **Path A** -- one genesis validator | the validator operator, on their own node | **yes** -- it is already theirs, and `InitEnclave` needs it there |
| **Path B** -- several genesis validators | a coordinator, for everyone | **no** -- no operator sends a key to a coordinator |

Path A is the shorter road and is what a launch that starts with a single validator should
take.  It is also the path this project actually exercises: `init.sh --mainnet-source` was
validated end to end on M1 on 2026-09-01.  **Take Path A unless you have more than one
genesis validator.**

Either way, the bucket multisigs are the same (Phase 1 and 2), and no bucket key ever
reaches any build host.

### What is never anyone's to handle

| key | generated by | ever leaves? |
|---|---|---|
| bucket multisig members | each member, own device | **no** -- only the pubkey |
| genesis validator / pioneer | the operator, on the node | **no** |
| consensus (`priv_validator_key.json`) | `qadenad init`, on the node | **no** |
| jar / regulator / SS interval | *inside the enclave* at `InitEnclave` | **no** -- never exists outside |

The last row matters: `init-enclave` takes a `JarID` and a `RegulatorID`, but those are
**names**, not keys.  Only `args[0]` (the pioneer) is looked up in a keyring; the jar and
regulator keys are minted in the enclave (`GenerateNewMnemonic`, enclave.go).  You do not
create them and you cannot back them up.  Confirmed on M1: `jar1`, `regulator1` and `ss`
appeared in `intervalPublicKeyIDList` after `InitEnclave`, from nothing supplied.

---

## Every node runs SGX, and nothing here fails if you forget

Every node of a launch chain runs a real SGX enclave.  That is not a deployment preference: it is
the whole basis of the trust model, because a debug enclave's remote report can be forged by anyone.

**This applies to a mainnet-parameter TESTNET too.**  A testnet built from this document is a
rehearsal, and a rehearsal on debug enclaves rehearses nothing: attestation, sealed-key handover and
the measurement-gated upgrade are exactly the parts that only exist on SGX.  Run it on real SGX
hardware -- SGX1/SGX2 are exactly that -- and let the governance timings be the difference, not the
enclave.

### What has to be true of the machines

- **x86_64 Ubuntu.**  `ego` ships as an amd64-only `.deb` and the Intel SGX apt repo is gated on
  `arch=amd64` ([`ubuntu/setup_qadena_build.sh:122`](../ubuntu/setup_qadena_build.sh)), so **an ARM
  box cannot be a node of a launch chain at all.**  It can be a debug node, which is what the test
  docs describe, and that is a different thing.
- **`ubuntu/setup_qadena_build.sh` has been run, as root.**  It installs ego, docker and the SGX
  DCAP quote provider, and -- the part that is easy to miss -- adds the login user to the groups
  owning `/dev/sgx_enclave` and `/dev/sgx_provision`, which are two DIFFERENT groups (`sgx`,
  `sgx_prv`).
- **`/dev/sgx_enclave` exists.**  If it does not, the machine has no usable SGX and everything below
  silently produces a debug enclave instead.

**The build machine must have `ego` installed.**  `buildscripts/build.sh` decides SGX-vs-debug by
looking for `ego` on PATH -- deliberately, since ego is a build dependency and not a runtime one, so
an x86 box with no SGX devices can still produce correct SGX binaries.  A machine without ego
**cannot build SGX at all** and produces debug artifacts after printing one line.  Nothing later in
this document fails because of it.

What that costs you, from `build.sh`'s own note:

> a chain binary built without the tag on an SGX node verifies real quotes with the debug verifier,
> which means it **ACCEPTS FORGED DEBUG REPORTS while believing it has attestation**.

So the failure is not "the chain will not start".  The chain starts, joins, produces blocks, passes
every suite -- and accepts forged attestations for its whole life.

### Check all three, before genesis and again before launch

```sh
command -v ego                       # 1. on the BUILD machine.  No ego, no SGX build.
```

```
build.sh: ego is installed, so building for SGX (chain binary WITH -tags realenclave).
```

2. That line must appear in the build output.  Its opposite -- `--no-sgx: building DEBUG
   artifacts` -- means stop.

```sh
grep '^qadenad_enclave.identity_mode' <package>/manifest.txt    # 3. must read: sgx
```

3. The package records which identity mechanism it carries, and this is the **package's** property
   rather than the building machine's -- which is what makes it worth checking on the node that
   will actually run it.  A missing key means the package carries no enclave at all (a chain-only
   release); for a launch chain -- mainnet or testnet -- require the key and require `sgx`.

**Never pass `--no-sgx` or `--debug-build`** for anything that will touch a launch chain.  Treat
`--skip-enclave` with the same suspicion: it was meant to rebuild only the chain binary and leave
MRENCLAVE alone, and it silently dropped `-tags realenclave` as well -- every joiner was then
refused with a bare "Invalid enclave" and nothing in the log said why.

### Build it, package it, and distribute THAT

```sh
buildscripts/build.sh --build-sgx
buildscripts/package_release.sh --out /tmp/pkg
```

`--build-sgx` is a reproducible docker build and takes roughly **24 minutes**.  It needs a CLEAN
working tree, because it runs `git clean -fd` first -- **uncommitted work is deleted.**

`package_release.sh` REFUSES to package an unsigned enclave from a machine that has ego.  That is
the accidental-debug-package guard: an unsigned binary on an ego machine means the build did not do
what you thought.  It records `qadenad_enclave.identity_mode: sgx` in the manifest, and `install.sh`
on the target then requires ego to read the measurement back.

**Build once, distribute.**  The build is reproducible, so installing every other node from the
package built here makes their measurements match **by construction**.  Building nodes independently
is where drift bites -- and `EnclaveIdentity` is keyed by measurement, so a node whose enclave
differs by one byte is refused by `verifyRemoteReport` with an error naming the measurement rather
than the cause.

Install on each node **as the user who will own it, never with `sudo`**.  It writes only into that
user's `~/qadena` and nothing in it needs root; a sudo install leaves the tree root-owned and the
operator's own CLI then fails on an unreadable `config/client.toml`.  Opening `/dev/sgx_*` is a
group-membership question, which `setup_qadena_build.sh` already arranged.

The `enclaveIdentityList` measurement in Phase 0 below must be the **real MRENCLAVE of the shipping
SGX build**, and registering a new one by governance is `scripts/gov_register_enclave_identity.sh` --
never the test fixture.

### What SGX changes about running the node

| | debug | **SGX (every launch-chain node)** |
|---|---|---|
| identity | a `go:embed`-ed string, e.g. `unique047` | a 64-hex measurement from `ego uniqueid` |
| root | not needed | **required** -- the enclave opens `/dev/sgx_enclave` |
| `export-private-state` | works, incl. `--digest-only` | **refused** |
| build | plain `build.sh` | `build.sh --build-sgx`, ~24 min, clean tree |

**Inspecting enclave state.**  `export-private-state` is refused on a real enclave, so the digest
debug builds use to compare private state does not exist.  What is available is

```sh
qadenad enclave store-hash
```

which returns per-store hashes and never their contents.  It covers the ten MIRRORED stores only:
the genuinely private tables -- the PCXY index, the AML window -- have no SGX-safe equivalent yet.
**Worth knowing before you need it: every divergence found on this chain so far was in a table
`store-hash` does not cover.**

Reproducibility itself is checked by `testscripts/regression.sh --with-sgx`, which builds the
enclave twice and requires both to measure identically.  That is test tooling, but it is the check
that backs "build once, distribute" -- run it before you trust a build you intend to launch from.
The SGX1/SGX2 fleet procedure is [HOWTO-TEST-SGX-BRINGUP.md](HOWTO-TEST-SGX-BRINGUP.md).

---

## Phase 0 -- close the decisions that genesis freezes

None of these can be changed later by governance.

| decision | status |
|---|---|
| transaction and credential keys: same key or separate custody | **same key** (2026-09-01) |
| `update_credential_policy_version` | **2** -- must match what the enclave binary implements |
| pricefeed markets at genesis | **three**: `cn:qdn:usd`, `cn:qdn:php`, `fn:php:usd` |
| `blocks_per_year` vs real block time | **MEASURE IT** on the real validator set -- see Traps |
| `enclaveIdentityList` measurements | real MRENCLAVE of the shipping SGX build |
| governance timings | 72h / 6h expedited / 24h deposit, with a written sunset trigger |

---

## Phase 1 -- the bucket key ceremony (both paths)

### Each multisig member, on their own device

```sh
qadenad keys add <member> --ledger              # or --keyring-backend file
qadenad keys show <member> -p                   # publish ONLY this
```

They send the **pubkey JSON**.  Never a mnemonic, never an armored export.  A member who
sends a private key has destroyed the property the multisig exists for, and the only remedy
is a new key and a new address.

Members per bucket, from `tokenomics/allocations.csv` (`custody_final`):

| buckets | members |
|---|---|
| Long-Term Reserve (4-of-7), Public Sector (5-of-7) | 7 each |
| Adoption, Wallet Incentive Pool, Foundation, Grants, Personnel, Backers, Founders, Node Ops (3-of-5) | 5 each |
| Contingency (2-of-N) | per the CSV |

### Deriving the addresses, holding no private keys

```sh
for m in m1 m2 m3 m4 m5; do
  qadenad keys add $m --pubkey "$(cat $m.pub)" --keyring-backend file --home ./coord
done
qadenad keys add adoption --multisig m1,m2,m3,m4,m5 --multisig-threshold 3 \
                          --keyring-backend file --home ./coord
qadenad keys show adoption -a
```

Imported pubkeys show `type: offline`; the derived multisig shows `type: multi`.  Any attempt
to extract a key fails with *"private key extraction works only for Local"* -- which is the
check that the ceremony worked.

**Every member independently re-derives and confirms the same address.**  A multisig address
is a pure function of (member pubkeys, threshold, ordering); two different answers means
someone has the wrong pubkey set or the wrong order.

Addresses go into `tokenomics/allocations.csv` **by hand**.  That file is human-owned
(HARD RULE 1) and the tooling is barred from writing it.

---

### When the foundation holds every key (day one)

The section above is the **distributed** shape: real members, on their own devices, sending only
pubkeys.  That is where a bucket ends up, not where it starts.  The brief's LATE ARRIVAL section is
explicit that at genesis *"almost nobody's address is known"* -- the buckets exist, the members
arrive later, and until they do the **founder holds every member key**.

That is a legitimate day-one custody model, not a shortcut.  What separates it from a test fleet is
not the topology -- both have one holder -- but **how the keys are minted**: an encrypted keyring,
and every mnemonic captured as it is created.

```sh
foundation_scripts/derive_launch_keys.sh \
    --home          ~/launch/coord \
    --mnemonics-dir ~/launch/mnemonics \
    --out           ~/launch/addresses.csv \
    [--passphrase-file ~/launch/pass.txt]      # else it prompts, dozens of times
```

It mints every member key, derives each bucket's multisig, and writes the CSV that Phase 2's
`--apply` consumes.  The account list comes from `fill_launch_config.py --template`, so the two
cannot drift.  It is idempotent -- existing keys are skipped, so an interrupted run resumes -- and
if no `qadenad` exists it builds a throwaway one into a temp directory and deletes it on exit.

**Do NOT use `fill_launch_config.py --dev-keys` for this.**  It does the same shape but mints into
`--keyring-backend test`, an UNENCRYPTED keyring, and stamps every row *"DEV THROWAWAY KEY -- never
for mainnet"*.  That is right for a fleet you purge and wrong for a genesis that freezes these
addresses forever.

Three things this produces that you must treat as the deliverable:

| output | why it matters |
|---|---|
| `~/launch/mnemonics/*.mnemonic` (0600) | **the only recovery that exists.**  Back it up offline, off that machine, before going further |
| `~/launch/coord` | the encrypted keyring.  NOT `$QADENAHOME` -- `init.sh` does `rm -rf` there, and the script refuses that path for exactly that reason |
| `~/launch/addresses.csv` | feeds Phase 2 |

A multisig gets no mnemonic file, correctly: it holds no private material of its own, being a pure
function of its members' pubkeys, the threshold and their order.  Losing enough *member* mnemonics,
though, leaves a bucket that genesis says holds billions and nobody can sign for.

**Distributing membership later is a migration, not an edit.**  Real members bring new pubkeys,
which produce a new multisig address, which means moving the funds -- not changing a config file.
Worth knowing before genesis freezes the addresses.

---

## Phase 2 -- render the config

`config/launch-config.yml` is the tracked **template**: every holder value is a
`TODO_ADDR_` placeholder and it is never filled in place.  Rendering produces an
**instance**, which is a build input for one chain:

```sh
foundation_scripts/fill_launch_config.py \
    --apply    addresses.csv \
    --out      ~/launch/mainnet-launch-config.yml
```

The **validator account is left for the node to mint**: its `address:` line is stripped so the
node's own keyring supplies the key, and its other references become `<name>PubKID` for
post-init substitution.  Which account that is comes from `validators[0].name` in the template
-- there is no flag, because the only thing a flag ever did was let you name the wrong account,
and naming the wrong one produced a validator WITH an address: no mnemonic prompt, and a gentx
nothing could sign.  `--no-generate` opts out entirely, for a genesis whose validator signs
somewhere else.

**Keep `--out` outside the repo.**  A `--build-reproducible` build runs
`git checkout -f && git clean -fd` and deletes untracked files inside it.

### The cross-check, and why it is fatal

`--apply` reads the two CSVs for different things: **addresses** from `addresses.csv`, **amounts**
from `allocations.csv`.  Nothing else in the toolchain compares them to each other.  So before it
writes anything, it checks every account both files name and **exits non-zero on any
disagreement**:

```
ADDRESS MISMATCH -- allocations.csv and addresses.csv disagree:
  adoption
      allocations.csv : qadena1zzzz...
      addresses.csv   : qadena1w3n8...

Nothing written.  One of the two files is stale -- reconcile them before rendering.
```

A mismatch is never a legitimate state: either step 3 was filled from a stale `addresses.csv`, or
the keys were re-derived afterwards.  It is fatal rather than a warning because the failure is
otherwise **silent and total** -- the instance would be internally consistent, the genesis would
build, every later assertion would pass, and the wrong key would control the bucket.  The only
other thing that could notice is `verify_genesis` assertion 5, which is exactly what
`--allow-placeholders` relaxes on the test path.

Before step 3 there is nothing to compare, so it says so and continues:

```
  NOTE: 12 account(s) still hold a PLACEHOLDER address in allocations.csv,
        so they could not be cross-checked: adoption, backers, ...
        The instance is still valid -- addresses come from addresses.csv, not from that column.
        But init.sh --mainnet-source WILL REFUSE until step 3 fills them (assertion 13).
```

Once step 3 is done it confirms the join instead:

```
  cross-checked 12 address(es) against allocations.csv: all agree
```

---

## Phase 3A -- build and launch (one genesis validator)

Run **on the validator's own machine**, by the operator.

```sh
cd ~/qv3 && ./buildscripts/init.sh \
    --advertise-ip-address <this node's public ip> \
    --mainnet-source     ~/launch/mainnet-launch-config.yml \
    --pioneer-mnemonic   "$(cat ~/launch/pioneer-mnemonic.txt)"
```

Omit `--pioneer-mnemonic` and it prompts, hidden, **before anything is destroyed** -- so the
mnemonic need never appear in shell history or `ps`.  Prefer the prompt on any launch chain: the
mnemonic is the validator's only recovery on a testnet exactly as it is on mainnet.

What happens, in order: the pioneer id is read from `validators[0].name`; `$QADENAHOME` is
wiped; the instance is copied to the working `config.yml` and the mnemonic injected **into
that copy only**; `ignite chain init` mints the key, creates the accounts and signs the
gentx; `setPubKAndPubKID.sh` substitutes `<name>PubKID` in the *generated genesis*; and the
build asserts no placeholder survived.

> **The mnemonic is the validator's only recovery.**  `ignite` will happily mint a key for an
> account given neither address nor mnemonic -- and print the mnemonic once, where nothing
> captures it.  That yields a funded validator nobody can ever sign for.  Supply it.

Then:

```sh
./scripts/start_qadena.sh
```

### Verify, in this order

1. **blocks advance against the wall clock** -- not `catching_up`, which lies on a halted node
   (see [HOWTO-CHAIN-RECOVERY.md](HOWTO-CHAIN-RECOVERY.md))
2. `moniker` matches the keyring key name
3. the pioneer appears in `intervalPublicKeyIDList` with `nodeType: pioneer`
4. `jar`, `regulator` and `ss` entries appeared -- proof the enclave initialised
5. balances match `allocations.csv` exactly

---

## Phase 3B -- several genesis validators: NOT CURRENTLY SUPPORTED

Only needed when more than one operator must contribute a validator at genesis: a coordinator
assembles a genesis with **no** validators, each operator signs their own gentx at home, and the
coordinator collects them.

**There is no tooling for this today, and the tool that used to claim it has been removed.**
`build_genesis.py` patched a bare `qadenad init` skeleton, which produces a genesis that is
arithmetically correct and will not run: `qadenad init` writes an EMPTY x/qadena section, so the
result carries no `enclaveIdentityList`, no `publicKeyList` and no pricefeed markets, and none of
the governance or staking parameters from `config/launch-config.yml`.  A chain built that way
fails after genesis, in a way that points at the enclave rather than at the genesis.

What Phase 3A does instead: the single genesis validator's own machine runs `init.sh
--mainnet-source`, which lets `ignite chain init` build the genesis from the rendered instance and
sign that validator's gentx.  Every other node joins afterwards as a normal validator
([HOWTO-ADD-LAUNCH-CHAIN-NODE.md](HOWTO-ADD-LAUNCH-CHAIN-NODE.md)), which is the path this project
actually exercises.

**If you need multiple validators AT GENESIS**, the work is to teach the rendered instance to carry
several `validators:` entries and collect their gentxs -- not to patch a skeleton.  Until then,
launch with one and add the rest.

---

## Traps

Each of these produced a chain that built cleanly and was wrong.  All were found by running
it, not by reading it.

### The EVM denom has no safe default

Omitting `genesis.app_state.evm` does not omit the module.  Cosmos EVM falls back to its own
default denom `aatom`, `bank.denom_metadata` declares only `aqdn`, and the node **panics at
startup**:

```
panic: error initializing evm coin info: denom metadata aatom could not be found
```

Genesis verifies, the chain builds, the node dies on first start.  Set `evm_denom: aqdn` and
`extended_denom_options.extended_denom: aqdn`.

The EVM **chain id** is a separate hazard: it is *parsed* from `chain_id`
(`<name>_<eip155>-<epoch>`), and a malformed one **fails silently** rather than erroring.

### The moniker is the pioneer ID

Omitting `validators[].config.moniker` is not neutral.  Ignite defaults it to `mynode`, the
chain builds, **the genesis is correct** -- and then `InitEnclave` looks for a key named
`mynode`, finds none, and the node runs forever without registering its enclave.

`moniker` MUST equal the validator's account name.

### `ignite chain init` wipes the keyring

It runs `appd init` under the hood, which removes the chain home -- **including
`$QADENAHOME/keyring-test`** -- and only then needs a key to sign the gentx.  A key restored
beforehand is destroyed.  The only ways a key can be there are a `mnemonic:` in the config
(Path A) or the gentx flow (Path B).

### `setPubKAndPubKID.sh` also substitutes a private key

It resolves `<name>PubKID` from the keyring, and substitutes `<name>PrivKHex` too --
`keys export --unarmored-hex --unsafe`.  Harmless on Path A, where the config carries no
such placeholder and the key is the operator's own.  **Never** let a config reach a build
host with a `PrivKHex` placeholder in it.

`init.sh` substitutes only when a placeholder is actually present, and always asserts
afterwards that none survived.

### `MsgUpdateParams` replaces the whole params object

`Params.Validate()` is a no-op for pricefeed, so a proposal carrying one market **silently
deletes every other**.  Any market change must carry the full set.

### `blocks_per_year` is a promise about block time

It is not measured; it is asserted, and mint pays against it for the life of the chain.  Ship
a `timeout_commit` that produces faster blocks than `blocks_per_year` assumes and the chain
over-mints permanently and silently.  Measure on the **real validator set** -- a single local
node's consensus rounds are not representative -- and set `blocks_per_year` from that.

### Remote builds need a login shell

`ssh <host> ./buildscripts/init.sh` does not source the profile that puts
`/usr/local/go/bin` on PATH, so `go version -m` reads nothing and the codegen check used to
report the plugins as the WRONG VERSION when they were fine.  The check now says so, but the
fix is the same one `testscripts/fleet_lib.sh` already uses:

```sh
ssh <host> bash -lc '<command>'
```

`ubuntu/setup_qadena_build.sh` must itself be run **as root** -- it uses `$SUDO_USER` to
install as the login user and then publish to `/usr/local/bin`.

### Funding an unidentified address is ONE-WAY

A whitelisted bucket may pay an address that holds no wallet and no credential -- that is the
onboarding rule, and it is how a node operator gets their self-bond
(`allowUnidentifiedDst := msg.SrcContract != nil`, enclave_scan_bank_send.go).

**Those coins cannot come back.**  The return trip has an unidentified SENDER, which no rule
permits, and the chain refuses it:

```
code 1159: This transfer cannot be AML-scanned; each party must be a wallet with eKYC data
           or on the scanned-contract whitelist
```

Measured 2026-09-01: a node address funded with 110,000 QDN could not return one QDN of it.

The address can still BOND (staking pays a module account, which is exempt) and still pay gas.
It simply cannot transfer out until it acquires an eKYC wallet or is added to
`scannedContractWhitelistList` by governance.

**So a mistyped recipient during funding is not a mistake you can undo.**  The tokens are not
lost -- a governance proposal whitelisting that address recovers them -- but recovery costs a
vote, and until it passes the money sits where it landed.  Check the address twice; a bucket
paying a node is exactly the operation where a fat finger is plausible and irreversible.

### `allocations.csv` is human-owned

Never edited by tooling, never auto-filled.  `fill_launch_config.py` writes a generated
instance via `--out` and refuses to touch the template or the CSV.  A missing value is a
question for a human, not a default.
