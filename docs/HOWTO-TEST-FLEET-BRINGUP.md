# Bringing up a TEST fleet (M1-M4, or SGX1-SGX2), and the re-share growth test

**This is test tooling.**  It drives `testscripts/`, and it takes shortcuts a deployment must not:
above all, one workstation holds every bucket multisig member's key, so the funding ceremony can be
performed without a second person.  A real bring-up is manual and lives in
[HOWTO-LAUNCH-CHAIN-BRINGUP.md](HOWTO-LAUNCH-CHAIN-BRINGUP.md).

One script brings up a fleet: `testscripts/fleet_bringup_with_tests.sh`.  It tests
**nothing** unless you schedule it, and the schedule is the command line.

It replaced `full_fleet_bringup.sh`, which ran a fixed order (build, regression,
package, install, soak, join).  Everything that script did is a schedule this one
accepts -- its regression is a `--test` before the first `--joiner`, its soak is a
`--test` last.  Two of its behaviours are deliberately **not** reproducible here, and
they are why it went:

- **it started the soak before the joins.**  The soak and the joins both spend from the
  treasury, so they collide on the account sequence.  That failed a real run mid-join
  (`expected 143, got 142`) after surviving the two joins before it.  Here the soak may
  only be scheduled last.
- **it joined `--until 6`, leaving joiners unbonded** -- so they never proposed, never
  became addressable, never became SS key owners, and phase 8's peer agreement never ran
  at all.  Here every joiner goes through phase 8.

`testscripts/fleet_lib.sh` holds the helpers and the traps.  Read it before changing
the bringup.

---

## The fleet

| name | address | notes |
|---|---|---|
| M1 | `alvillarica@192.168.86.162` | primary |
| M2 | `alvillarica@192.168.86.154` | |
| M3 | `alvillarica@192.168.86.52`  | **.52, not .53** |
| M4 | `alvillarica@192.168.86.136` | |

All aarch64 debug-enclave boxes: no SGX, no ego, ~3 minute builds.

| name | address | notes |
|---|---|---|
| SGX1 | `alvillarica@192.168.86.120` | primary |
| SGX2 | `alvillarica@192.168.86.140` | |

**x86_64 with real SGX**: `/dev/sgx_enclave` and `/dev/sgx_provision` present, ego at
`/usr/local/bin/ego`, 2 cores, **~41 minute builds**.  Nothing about the aarch64 line
above applies to these two -- do not read it as covering the whole table.

---

## The phases

| # | phase | notes |
|---|---|---|
| 1 | preflight | ssh, arch, enclave measurement |
| 2 | check the primary | `--quiesce` stops its continuous regression first |
| 3 | mint the joiner's pioneer key | `add_full_node.sh --stop-for-funding` |
| 4 | **fund the joiner** | bank send, or a fee grant under `--foundation-sponsored` |
| 5 | join | state-sync or block-sync |
| 6 | start the joiner and catch up | |
| 7 | convert to validator and split the stake | **runs only with `--convert-to-validator`**; a joiner that never bonds never becomes an SS owner |
| 8 | peer agreement | |

**3 and 4 were one phase until 2026-09-01.**  Minting a key and PAYING for it are different
jobs with different owners: the mint is mechanical, while the funding depends entirely on who
holds the money.  Both funding branches resolve the granter with `keys show` **on the
primary**, so a bucket held as a 3-of-5 multisig whose members live on a workstation cannot be
used at all -- the phase fails before the join it was gating.

Split, the escape hatch is `--until 3`, fund by whatever ceremony that custody requires, then
`--from 5`.

### `--convert-to-validator`: declare the intent, get one funding point

`add_full_node.sh` makes a FULL NODE, and a full node may stay one forever: "this covers
JOINING only."  Validating is a separate act (`convert_to_validator.sh`), and the self-bond
is money only that act needs -- sent early to a node that never bonds, it is stranded, because
coins sent to an unidentified address CANNOT BE SENT BACK (HOWTO-LAUNCH-CHAIN-BRINGUP.md).

So the bond follows a DECLARATION, not a phase:

- **without `--convert-to-validator`**: a full node.  No self-bond anywhere, phase 3's
  ceremony instructions omit it, phase 7 is skipped.
- **with it**: the bond moves at the FUNDING phase (4), alongside the fee grant -- one
  intervention for whoever holds the money -- and phase 7 only converts.  Passing the flag is
  the statement that this node WILL bond, which is what makes the early send safe.

Both deliveries are idempotent (an existing grant and a present bond are skipped), so an
external custodian signs everything at `--until 3` and is never asked again.  Phase 3 prints
the exact `aqdn` bond amount so both transactions can be prepared in one sitting.

**Pass `--foundation-sponsored` on the `--until 3` run too**, if that is what you mean to do.
Phase 3 prints what has to be signed, and *what* has to be signed depends entirely on it -- a
recurring fee grant, or a plain transfer.  The flag is normally read by phase 4, which is the
phase you are skipping, so it is easy to leave off and be told to sign the wrong thing.  Phase 3
now names the mode it assumed, so check that line before starting a ceremony.

## The growth test (TESTING-BACKLOG item 107)

The re-share audit heals SS interval keys minted when the fleet was **smaller** than
it is now.  A fleet that arrives all at once never produces that case -- every key is
minted with all four pioneers already addressable, and the audit has nothing to heal.

Forcing rotations **between** joins is what manufactures the interesting state: keys
owned by 1, then 2, then 3 pioneers, which the audit must then bring up to the
current fleet size.

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.162 \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_reshare_audit.sh" \
  --joiner alvillarica@192.168.86.154 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.52 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.136 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/run_regression_continually.sh"
```

`--test` attaches to whatever node preceded it, so **the schedule is the command
line**.

### The same run, block-sync (faster, while iterating)

Identical except for the last line.  `--block-sync` skips stage F, where the primary
must pass the snapshot interval before a joiner can state-sync -- about 35 minutes.
See *Choosing a sync mode* below for what that costs you.

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.162 \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_reshare_audit.sh" \
  --joiner alvillarica@192.168.86.154 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.52 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.136 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/run_regression_continually.sh" \
  --block-sync
```

The growth test itself is unaffected: bonding, addressability, re-sharing and the
audit are identical either way.  What block-sync does not exercise is the joiner
seeding its enclave store from a snapshot.

### What each position is for

| after | fleet | the audit should |
|---|---|---|
| M1 | 1 | do nothing -- target is 1 and every key already has 1 owner |
| M2 | 2 | **heal the size-1 keys 1 -> 2** |
| M3 | 3 | heal size-1 and size-2 keys -> 3 |
| M4 | 4 | heal everything -> 4; **the threshold crosses 1 -> 2 and `shamir.Split` runs for the first time** |

The audit after M2 is the first one that can fail meaningfully.  Everything before it
is a baseline.

---

## The full M1-M4 run: growth, then regression, then an upgrade, then a soak

The growth schedule above proves the audit heals as the fleet grows.  This one adds the
three things that only mean anything once the fleet is complete: a full regression with
the chain-restarting suites, a governance upgrade of every node, and a soak.

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.162 \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_reshare_audit.sh" \
  --joiner alvillarica@192.168.86.154 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.52 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
  --joiner alvillarica@192.168.86.136 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/regression.sh" \
  --test-local "./testscripts/test_fleet_upgrade.sh \
      --primary alvillarica@192.168.86.162 \
      --joiner alvillarica@192.168.86.154 \
      --joiner alvillarica@192.168.86.52 \
      --joiner alvillarica@192.168.86.136" \
    --test "./testscripts/run_regression_continually.sh"
```

> Add `--foundation-sponsored` to any of these to run it **toll-free**: no joiner is
> sent coins and none holds a treasury.  See "Choosing a funding mode" below.

### Why the tail is in that order

**`regression.sh` with no `--skip`, and only here.**  `enclave-rollback` and
`enclave-crash` stop and restart the node they run on, so they are only safe once the
fleet can survive losing this one.  After a four-way bond M1 holds about **31%** of the
voting power, leaving ~69% against the 66.7% a quorum needs -- so the chain keeps
committing while M1 restarts.  Do not move this earlier: on a two-node fleet the primary
holds ~50% and the same command halts the chain.  You do not have to remember that --
`regression.sh` now runs the same auto-skip the soak does and will refuse the disruptive
suites when this node's stake matters, saying so.  `--no-auto-skip` overrides it.

**The upgrade entry goes after every joiner, never before.**  It bumps the enclave
identity and both versions on the primary, commits that temporarily, and rolls the
release to *every* node by governance -- then asserts each one swapped and that the
sealed keys survived.  A node joining after it would be installed from the stage-D
package, which measures the OLD enclave, and the chain would refuse it.  The script
refuses that ordering rather than letting it produce a confusing failure.

It is the one entry that runs **from your workstation** rather than on the primary.  That
distinction is the whole reason it is a flag of its own: `--test` is defined as *runs on
the primary* (`run_scheduled` -> `rsh_build "$PRIMARY"`), and the primary cannot ssh to the
joiners --

```
M1->154: Permission denied (publickey,password)
```

-- so `--test "./testscripts/test_fleet_upgrade.sh …"` would die in its own preflight with
`cannot ssh to <joiner>`.

`--test-local "<cmd>"` is the general form used above: same positional ordering, same
halt-on-failure, but run **here** instead of on the primary.

**The one cost of spelling it out** is that the fleet is typed twice -- once as
`--primary`/`--joiner` for the bringup, once inside the `--test-local` string.  Those two
lists must match.  If they drift you upgrade a different set of nodes than the run built,
and it surfaces much later as a joiner refused on a measurement mismatch rather than as
anything that looks like a typo.  `--test-fleet-upgrade` exists as sugar that takes the
membership straight from the run and cannot drift:

```sh
  --test-fleet-upgrade \
```

Both go through the same executor, so they run, log and fail identically.  Use the sugar
unless you need the fleet in the string to differ from the fleet being built.

**The soak last**, because it never exits.  Anywhere else it either blocks the run or
shares the chain with whatever follows, and the collisions read as chain bugs.

### What the upgrade actually changes

Three files, via `increment_id` / `increment_version` in `scripts/setup_env.sh`, which
write with `echo -n` -- these files carry **no trailing newline**, and
`test_unique_id.txt` is `//go:embed`-ed, so one added byte changes the measurement:

| file | now | after |
|---|---|---|
| `cmd/qadenad_enclave/test_unique_id.txt` | `unique061` | `unique062` |
| `cmd/qadenad_enclave/version.txt` | `1.1.23` | `1.1.24` |
| `cmd/qadenad/version.txt` | `1.1.28` | `1.1.29` |

The **chain** version is the one that makes the upgrade real: the governance plan is
named `v<chain version>`, and a plan whose name the running binary already handles is a
silent no-op -- no halt, no swap.  The enclave version must move because the attested
handover requires strictly greater.

`test_signer_id.txt` is deliberately **not** touched.  In a debug build the signer and
unique ids *are* the sealing keys; bumping the signer once moved `signer051 -> signer052`
and the upgraded enclave panicked in `getPrivKCache` with "Couldn't unseal, unrecognized
prefix", while the handover reported success.

The bump is committed on the primary and reset on exit -- `upgrade_fleet.sh` refuses a
tree that matches no commit, and an SGX build's `git clean -fd` would discard an
uncommitted bump and rebuild the identical measurement while looking like it worked.

---

## A launch-chain run, end to end in one command

A devnet needs nothing but the fleet.  A **launch chain** (`--mainnet-source`) also needs the
accounts the suites expect -- above all a `treasury`, which genesis does not contain because a
launch genesis holds buckets and validators only.  Funding one is a bucket ceremony, so this used
to be three commands with a manual signing session wedged between them.

`--test-local` closes that, because the ceremony's keys are on **this workstation** and
`--test-local` is the one scheduling slot that runs here rather than on the primary:

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.162 \
  --joiner alvillarica@192.168.86.154 \
  --joiner alvillarica@192.168.86.52 \
  --joiner alvillarica@192.168.86.136 \
  --block-sync \
  --mainnet-source ~/qadena-dev-vault/fleet-launch-config.yml \
  --pioneer-mnemonic-file ~/qadena-dev-vault/pioneer-mnemonic.txt \
  --funder qfi-pioneer1 --fund-qdn 10100 --stake 10000 \
  --test-local "./testscripts/provision_from_bucket_local.sh --name treasury --from-bucket adoption --amount 50000000 --stake 10000000 --whitelist --host alvillarica@192.168.86.162" \
  --test "QADENA_PIONEER=qfi-pioneer1 QADENA_GENESIS_NODES=qfi-pioneer1,wallet-incentive-pool QADENA_PF_TARGET=fn:php:usd QADENA_PF_CONTROL=cn:qdn:usd ./testscripts/regression.sh"
```

### Why this is test tooling and must stay that way

`provision_from_bucket_local.sh` **signs for the bucket** -- three of five member keys, one after
another, unattended.  It can only do that because this workstation holds all five, which is
precisely the arrangement a real bucket exists to prevent.  `scripts/provision_account.sh` refuses
to sign and waits for a human instead; that is correct there and is not a limitation to route
around.  The wrapper does the ceremony and then hands straight back to `provision_account.sh` for
staking and the whitelist, so the production logic is borrowed rather than reimplemented.  The
manual procedure is [HOWTO-LAUNCH-CHAIN-BRINGUP.md](HOWTO-LAUNCH-CHAIN-BRINGUP.md) Phase 4.

### Two rules the command line has to obey

**`--test-local` goes after the LAST `--joiner`.**  The provisioning stakes the treasury across
every *bonded* validator, and voting power decides whether the whitelist proposal passes.  Run it
earlier and it delegates to a partial set, then submits a proposal short of quorum -- which
**expires** rather than failing, with every transaction reporting success.

**No argument may contain a space.**  The dispatcher word-splits scheduled commands with
`${=...}`, so a quoted `--reason "provisioned from adoption"` arrives as three words and the next
one is read as the address.  That is why the wrapper takes no `--reason`.

### The environment the suites need on a launch chain

The devnet's names are not the launch chain's, so regression is pointed at the right ones by
environment rather than by editing scripts:

| variable | launch chain | why |
|---|---|---|
| `QADENA_PIONEER` | `qfi-pioneer1` | the devnet's validator is `pioneer1` |
| `QADENA_GENESIS_NODES` | `qfi-pioneer1,wallet-incentive-pool` | genesis registration set |
| `QADENA_PF_TARGET` | `fn:php:usd` | the devnet's `cn:eth:usd` does not exist here |
| `QADENA_PF_CONTROL` | `cn:qdn:usd` | any market credential fees do NOT convert through |

---

## Adding ONE node to an existing test fleet

The manual, operator-side procedure is [HOWTO-ADD-LAUNCH-CHAIN-NODE.md](HOWTO-ADD-LAUNCH-CHAIN-NODE.md).  This is the same
sequence driven from a workstation, which ssh-es into both machines and watches them from outside:

```sh
testscripts/nth_node_bringup.sh --primary <ip> --joiner <ip> --pioneer <name> \
    --until 3 [--foundation-sponsored <granter-addr>] [--convert-to-validator]
# ...run the funding ceremony (phase 3 prints it, amounts included)...
testscripts/nth_node_bringup.sh --primary <ip> --joiner <ip> --pioneer <name> \
    --from 5 --until 8 <same flags>
```

Pass the SAME flags on both runs — they select what phase 3 tells you to sign and what phase 5
waits for.  Phases 4 and 7 skip money already delivered, so the ceremony is never repeated.
See the phase table above for what each one does.  The ceremony itself — what the sponsor signs,
and why a joiner holds no liquid balance — is [HOWTO-ADD-LAUNCH-CHAIN-NODE.md](HOWTO-ADD-LAUNCH-CHAIN-NODE.md) step 2.

And above all: never re-run phase 3 with a DIFFERENT pioneer name against a joined node.  It
wipes.

## SGX1 + SGX2

**The growth test does not belong here and is not written out for this fleet**, because
copying it is the mistake.  Both halves of it are debug-only and are refused when
`--realenclave` is set:

| command | driven by | on real SGX |
|---|---|---|
| `update-ss-interval-key` | `test_ss_key_rotation.sh` | refused -- `SKIPPED: the enclave refused a forced key rotation` |
| `audit-ss-keys` | `test_ss_reshare_audit.sh` | refused -- `SKIPPED: this is a real SGX enclave` |

So a growth schedule pointed at SGX is a NO-OP: the run finishes green having exercised
none of the SS machinery it appears to test.  The suites skip loudly and say what was lost
-- that part is working -- but the SCHEDULE would be the lie, reading like the M1-M4 growth
test while being an empty shell.  Observed 2026-08-30: eight scheduled tests, eight skips.

The re-share machinery is covered on a debug enclave (M1-M4) and by the unit tests around
`planSSReshare`, plus `x/qadena/common/vshare_test.go` and
`x/qadena/keeper/interval_public_key_i_d_test.go`.

**What an SGX run is actually for**, and it is not nothing -- every one of these had never
been exercised before 2026-08-27:

- the reproducible SGX build, and an ego-signed MRENCLAVE that matches genesis
- the joiner's measurement matching the primary's enclave
- a state-sync join that seeds the joiner's enclave store from a snapshot, then agrees on
  the app hash
- a real regression soak against SGX hardware

### The full SGX1 + SGX2 run

The M1-M4 tail works here; only the SS positions are dropped, because they are the ones
that cannot execute:

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.120 \
  --joiner alvillarica@192.168.86.140 \
    --test "./testscripts/regression.sh" \
  --test-local "./testscripts/test_fleet_upgrade.sh \
      --primary alvillarica@192.168.86.120 \
      --joiner alvillarica@192.168.86.140" \
    --test "./testscripts/run_regression_continually.sh"
```

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --foundation-sponsored \
  --block-sync \
  --primary alvillarica@192.168.86.120 \
  --joiner alvillarica@192.168.86.140 \
    --test "./testscripts/regression.sh" \
  --test-local "./testscripts/test_fleet_upgrade.sh \
      --primary alvillarica@192.168.86.120 \
      --joiner alvillarica@192.168.86.140" \
    --test "./testscripts/run_regression_continually.sh"
```

Three things differ from the M1-M4 run, and all three are properties of this fleet rather
than of the schedule:

**`regression.sh` gets less than it does on M1-M4, and correctly so.**  With two nodes the
primary holds ~50% of the voting power, so its auto-skip refuses `enclave-rollback` and
`enclave-crash` -- stopping the only node that can keep the chain committing would halt it.
On M1-M4 the primary sits near 31% and both suites run.  You will see the reason printed:

```
this node holds 49.9510% of voting power -- stopping it HALTS the chain
auto-skip: skipping enclave-crash,enclave-rollback  (override with --no-auto-skip)
```

**The upgrade is measured differently.**  `test_fleet_upgrade.sh` bumps the same three
files, but on SGX the identity is not the embedded string -- it is the MRENCLAVE ego
computes from the signed binary, which moves because `version.txt` is embedded and the
bytes change.  The test reads the measurement from each node rather than assuming the
bumped value, so it works on both kinds of enclave; on SGX you will see a 64-hex
measurement where M1-M4 shows `unique062`.

**Its sealed-state check inverts.**  On a debug enclave the params file is readable, so the
regulator key is compared byte-for-byte and every pre-upgrade report is decrypted.  On SGX
that file is ciphertext to everyone including the test, so it asserts the opposite -- that
the file really *is* opaque -- and reports plainly that decryption was not verified.  A
readable params file under a real enclave would mean every private key on the node is
exposed on disk, and this is the one place positioned to notice.

**Budget about two hours.**  The bringup build is ~41 minutes on these 2-core boxes, and
the upgrade entry does a second full build of its own.

If you only want the fleet up and soaking, drop the middle two entries and keep the soak --
but keep *at least one* `--test`: a bringup with none also skips `wait_addressable`, and
that gate is what proves a joiner is a real SS key owner.  `--block-sync` is worth adding
while iterating; leave it off for a run that counts, since state-sync is the path that
seeds the joiner's enclave store from a snapshot.

**Two nodes reach none of the audit rows, and that is a property of SGX, not of the count.**
It is tempting to read SGX2 as "position M2" and expect it to heal the size-1 keys 1 -> 2.
It cannot: the audit is refused on this hardware, so there is no row to reach.  Even the
count argument only applies on a debug fleet, where a two-node run genuinely stops short of
the M4 threshold crossing and `shamir.Split` never runs.  For any of it, use M1-M4.

**On SGX, keep the one soak `--test` above** -- see *an empty schedule is a deploy* under
*Traps this has already hit* for why a schedule with none at all is worse still.

### Real SGX changes three things

The first SGX fleet run was 2026-08-27; every run before it was a debug enclave on ARM.

- **Nothing needs a flag.**  Preflight probes both hosts and prints
  `build SGX (ego and devices present)`.  Do not pass `--build-sgx`; it is for forcing
  the case the probe cannot see.
- **Do not bump `test_unique_id.txt`.**  That convention under *Before you run* exists
  because a debug enclave takes its identity from that embedded string.  On SGX the
  measurement is computed by ego from the signed binary -- a real MRENCLAVE, e.g.
  `cd2b86aeea28d059d6f87420c0ba27c57bad91b4ed3d0ce7696ed70bf7da25a4` -- and editing the
  file changes nothing that matters.
- **Budget ~41 minutes for the build**, not the ~24 quoted elsewhere: these boxes have
  2 cores.

### Block-sync from genesis works again

Item 107's older note that the chain was unjoinable by block-sync (an AppHash halt at
height 3) described a **version-skew** defect: history written by 1.1.16, replayed under
1.1.17's added gas-metered read, with no upgrade height gating it.  A fleet bringup does
not hit it, because genesis is created by the same build the joiner replays with.  On
2026-08-27 SGX2 block-synced from genesis and ended at `earliest=1` -- the first node on
any fleet to do so, M2-M4 having all state-synced and so all reporting `earliest=2001`.

That is worth checking on any block-synced joiner, because it is the one field that
distinguishes the two paths after the fact:

```sh
curl -s localhost:26657/status | jq -r '.result.sync_info.earliest_block_height'
```

---

## Stopping and cleaning a fleet

`testscripts/stop_fleet.sh` stops every node, verifies it stayed stopped, and removes only
what you ask it to.

```sh
./testscripts/stop_fleet.sh \
  --node alvillarica@192.168.86.162 \
  --node alvillarica@192.168.86.154 \
  --node alvillarica@192.168.86.52 \
  --node alvillarica@192.168.86.136 \
  --purge --reap-archives --clean-logs --immediate
```

**Nothing is deleted by default.**  Stopping is safe and repeatable; deleting is neither, so
each kind of removal is opt-in:

| flag | removes | what that costs |
|---|---|---|
| *(none)* | nothing | stop, verify, report disk |
| `--purge` | `~/qadena` | chain data **and the keyring** -- on a joiner, the only copy of its pioneer key.  Takes `~/qadena/logs` with it, which is the large one (540M on M1) |
| `--reap-archives` | `~/qadena.pre-bringup.*.bak` | nothing, and it is the one to reach for on its own -- see below |
| `--clean-logs` | `~/<repo>/logs` contents | **includes `regression-history`** -- `suites.tsv`/`history.tsv`, i.e. where *"no failures in 147 scored runs"* comes from |
| `--immediate` | -- | ends an in-flight regression now instead of waiting it out |

**`--reap-archives` earns its place.**  Stage A of a bringup *archives* each joiner's old
`~/qadena` rather than deleting it, and nothing else ever reaps those.  A full clean of
M1-M4 on 2026-08-30 reclaimed about 11G: ~8.7G of node homes and ~2.5G of stale `.bak`
directories, roughly 830M per joiner per previous run.

**`--clean-logs` destroys a soak's accumulated verdict**, not just noise.  It is right
before a clean-chain run and wrong if you have not read the last result yet.  `/logs` is
gitignored, so emptying it does not dirty the checkout -- which matters, because the
bringup preflight refuses a dirty tree.

### What it protects you from

Each of these has cost a run:

- **every host is preflighted before any is touched.**  With `--purge` armed, an
  unreachable host aborts with `nothing has been stopped` -- rather than leaving half the
  fleet purged and half running.
- **the soak is stopped before the node.**  A continuous regression left running through a
  teardown does not stop, it starts *failing* against a chain being deleted underneath it,
  and those failures resurface in the next run's logs looking like chain bugs.
- **systemd is asked where a unit exists.**  "Nothing is running" is not "nothing will
  run": `Restart=on-failure` brings a node back seconds after a direct kill appears to
  work.
- **the start-limit lockout is cleared.**  A node that crash-looped leaves its unit
  `failed`, and `StartLimitBurst=5` makes the *next* start fail with "Start request
  repeated too quickly" -- so a later bringup fails to start a node that is perfectly fine.
  M1 needed exactly this on 2026-08-30.
- **nothing is removed on a host that is not verified stopped.**  Deleting under a live
  node leaves processes whose binaries no longer exist, and every later diagnosis then
  describes a machine that cannot be reasoned about.

Related: `testscripts/stop_regression.sh` stops just the continuous-regression loop, on one
host (`--host`) or locally.  `stop_fleet.sh` calls it per node.  Its `--immediate` ends the
in-flight run now rather than waiting for it to finish -- and resumes any enclave a killed
test left `SIGSTOP`ped, without which the option would manufacture the wedge it exists to
avoid.

---

## Before you run

**Free the archives.**  Stage A moves each joiner's `~/qadena` aside rather than
deleting it, and nothing ever reaps them.  Three runs left 67G of
`qadena.pre-bringup.*.bak` and took two joiners to 94% full.

```sh
for h in 154 52 136; do
  ssh alvillarica@192.168.86.$h 'rm -rf ~/qadena.pre-bringup.*.bak; df -h ~ | tail -1'
done
```

Keep the newest if you may still need a keyring; delete the rest.  They hold chains
whose genesis no longer exists once M1 is wiped.

**The primary's checkout must be clean.**  Preflight refuses otherwise, because the
build runs `git clean -fd` and would destroy uncommitted work.  `docs/static/openapi.yml`
is regenerated by builds and is the usual offender:

```sh
ssh alvillarica@192.168.86.162 'cd ~/qv3 && git stash -u'
```

**Bump the identity if you want a distinct measurement.**  Convention is three files
in one commit, and they carry **no trailing newline** -- the value is `//go:embed`-ed,
so an added byte changes the build:

```
cmd/qadenad_enclave/test_unique_id.txt   unique055 -> unique056
cmd/qadenad_enclave/version.txt          1.1.13    -> 1.1.14
cmd/qadenad/version.txt                  1.1.15    -> 1.1.16
```

**Push first.**  The primary builds from `origin/main`, so any test script the
schedule names must be pushed or the fleet runs the old one.

---

## Choosing a funding mode

By default every joiner is **sent 200,000 QDN** by bank send from the primary's
treasury (stage G, `nth_node_bringup` phase 4), and `add_full_node.sh` waits for that
balance before it will run `sync-enclave`.

`--foundation-sponsored [<granter-key>]` replaces that with a **fee grant**.  No coins
move, the joiner never holds a balance, and it needs no treasury of its own.  The
granter defaults to `treasury` because that is the key the primary already holds; in a
real deployment it is a foundation key.

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --foundation-sponsored \
  --primary alvillarica@192.168.86.162 \
  --joiner alvillarica@192.168.86.154 \
  ...
```

### What the grant covers, and why that matters

A node does not stop spending after it joins.  `sync-enclave` broadcasts three
messages, but `UpdateHeight` runs **per block** and drives SS rotation and re-share,
which broadcast two more:

```
MsgPioneerAddPublicKey                join + SS rotation
MsgPioneerUpdateIntervalPublicKeyID   join + SS rotation + InitEnclave
MsgPioneerUpdatePioneerJar            join + InitEnclave
MsgPioneerUpdatePublicKey             SS RE-SHARE
MsgPioneerUpdateJarRegulator          InitEnclave
```

The grant is a **PeriodicAllowance** over all five, with a per-period budget that
refills and **no expiry**.  Both parts are deliberate:

- A join-only grant is a trap.  The node joins, runs, and then fails its first SS
  rotation -- unable to pay for a message its grant does not list -- while still
  looking healthy.  SS participation is consensus-relevant here, so that is not a
  cosmetic failure.
- An expiring grant is the same trap with a delay.  SS rotation recurs for as long as
  the node runs, so the sponsorship has to as well.

Bounded three ways regardless: per-period budget, message allow-list, and an optional
total cap.  `scripts/foundation_sponsor_node.sh --join-only` gives the narrow expiring
grant if you actually want it, and warns about exactly this.

### What is NOT sponsored

**Validator self-bonds.**  `--stake` is unaffected and still comes from the operator's
own funds.  That is deliberate: slashing is keyed to the **infraction height**, so a
foundation that sponsored the bond would absorb every penalty while the operator risked
nothing -- and undelegating after the fact does not escape it.

### Requirements

- `scripts/foundation_sponsor_node.sh` must be on the **primary** (it ships in the
  release package; stage G fails with "install the release package first" if not).
- The granter key must be in the primary's keyring.

Stage G's banner and the run-directory note both record which mode was used, so a run
does not have to be reconstructed from a flag someone remembers passing.

---

## Choosing a sync mode

`--block-sync` skips stage F, where the primary must pass the snapshot interval
(2000 blocks, ~35 min at 1.5s) before a joiner can state-sync.

That wait is **once per run**, not once per joiner, so the saving is ~35 minutes
total.  It is a **different test, not a faster one**: state-sync seeds the joiner's
enclave store from a snapshot, and a block-synced joiner never touches that path --
which is one of item 107's assertions.

Use `--block-sync` while iterating.  Use the default for a run that is meant to count.

---

## Stages, and resuming

```
A0 preflight every host -- nothing is stopped or moved until all pass
A  stop any suite on the primary; archive each joiner's ~/qadena
B  build, WIPE $QADENAHOME, re-init genesis, start the primary
C  --test commands scheduled before the first --joiner
D  package what is actually running
E  install that package on each joiner
F  wait for the snapshot   (skipped by --block-sync)
G  join each joiner: nth_node_bringup --from 1 --until 8, then wait until
   addressable, then its --test commands
   (phase 4 funds the joiner -- by bank send, or by fee grant under
    --foundation-sponsored, in which case no coins move at all)
```

`--from <stage>` resumes.  Two things it does **not** do:

- **It skips the genesis wipe.**  A resumed run is not a clean-chain run, so it is
  not a growth test any more -- the keys you measure were minted on the previous chain.
- **It cannot re-join a joiner.**  `add_full_node.sh` refuses a pioneer name the chain
  has already seen, so resuming into stage G after a partial join needs a fresh
  `--pioneer-prefix`, or that node bonded by hand.

---

## Traps this has already hit

**Joiners must be bonded -- pass `--convert-to-validator`, phase 7.**  It is tempting to join `--from 1 --until 6` and
stop there, because converting re-splits stake -- the old bringup did exactly that.  For
a growth test it is wrong: a node that is not a validator never proposes a block,
`updateIsValidator`
publishes an external address **only under `IsProposer`**, so an unbonded joiner never
becomes addressable, never becomes an SS key owner, and every audit stays quiescent --
the suite goes green having healed nothing.  This script uses `--until 8`.

**Full paths on remote commands.**  `rsh_user` runs `zsh -lc`, and the node's bin is
not on a zsh login PATH -- `which qadenad` answers NOT-ON-PATH.  A bare `qadenad`
returns empty, which reads as "not ready yet" and stalls for the full timeout on a
fleet that was already correct.  Builds have the same problem one layer up, which is
why `rsh_build_detached` prepends `BUILD_PATH` under `bash -lc`.

**`pgrep` patterns must be bracket-classed** so an ssh command never matches itself.
A plain `pkill -f "run_regression_continually"` kills the ssh session carrying it.

**Processes being up is not health.**  On a small fleet one divergent node halts the
chain with every process still running, so the height must be seen to ADVANCE.
Phase 6 checks no validator reaches 2/3 for the same reason -- skipping it by hand is
what halted this fleet (item 108).

**An empty schedule is a deploy, not a growth test.**  `fleet_bringup_with_tests.sh`
tests nothing unless a `--test` asks for it, so a run with no schedule comes up green
having measured nothing.  The sharp edge is that `wait_addressable` is called from the
**first `--test` of each joiner** -- so a run with no tests also never waits for the
joiner to publish its external address, and the one gate that proves a joiner is a real
SS key owner silently does not run.  On 2026-08-27 that produced a healthy-looking
two-node SGX fleet whose addressability had to be confirmed by hand:

```sh
qadenad q qadena list-interval-public-key-id --limit 5000 -o json \
  | jq '[.intervalPublicKeyID[]? | select(.nodeType=="pioneer" and .externalIPAddress!="")] | length'
```

**`pgrep` counts are not evidence -- read the command lines.**  Checking whether a soak
is running with `pgrep -f "regression" | wc -l` returns 1 on an idle box, because the
ssh command carrying the query matches itself.  Bracket-class the pattern *and* pass
`-a`, so what matched is visible rather than inferred:

```sh
ssh $HOST 'pgrep -af "run_regression_continuall[y]"'
```

---

## Reading the result

Per-run logs land in `--run-dir` (default `~/qadena-fleet-runs/<stamp>`, plus a
`latest` symlink), one file per stage and per scheduled test.

The lines that matter:

```
addressable pioneers: 2 (>= 2)
deficient (< 2 owners): 7 -> 0
the audit acted: 7 deficient key(s) before, N selected, 0 after
```

A quiescent audit says `nothing was deficient and the audit correctly did nothing`.
That is a pass, but it is a baseline -- it proves the audit does no harm, not that it
heals.
