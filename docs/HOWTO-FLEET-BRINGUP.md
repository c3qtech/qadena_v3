# Bringing up a fleet (M1-M4, or SGX1-SGX2), and the re-share growth test

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
- **it joined `--until 5`, leaving joiners unbonded** -- so they never proposed, never
  became addressable, never became SS key owners, and phase 7's peer agreement never ran
  at all.  Here every joiner goes through phase 7.

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
  --test-fleet-upgrade \
    --test "./testscripts/run_regression_continually.sh"
```

### Why the tail is in that order

**`regression.sh` with no `--skip`, and only here.**  `enclave-rollback` and
`enclave-crash` stop and restart the node they run on, so they are only safe once the
fleet can survive losing this one.  After a four-way bond M1 holds about **31%** of the
voting power, leaving ~69% against the 66.7% a quorum needs -- so the chain keeps
committing while M1 restarts.  Do not move this earlier: on a two-node fleet the primary
holds ~50% and the same command halts the chain.  You do not have to remember that --
`regression.sh` now runs the same auto-skip the soak does and will refuse the disruptive
suites when this node's stake matters, saying so.  `--no-auto-skip` overrides it.

**`--test-fleet-upgrade` after every joiner, never before.**  It bumps the enclave
identity and both versions on the primary, commits that temporarily, and rolls the
release to *every* node by governance -- then asserts each one swapped and that the
sealed keys survived.  A node joining after it would be installed from the stage-D
package, which measures the OLD enclave, and the chain would refuse it.  The script
refuses that ordering rather than letting it produce a confusing failure.

It is the one entry that runs **from your workstation** rather than on the primary: a
`--test` runs on the primary, and the primary cannot ssh to the other nodes.

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

## SGX1 + SGX2 -- NOT the growth test

The schedule below is the one you will reach for, and it is the WRONG one for SGX.  It is
kept here only so the reason is attached to it:

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.120 \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_reshare_audit.sh" \
  --joiner alvillarica@192.168.86.140 \
    --test "./testscripts/test_ss_reshare_audit.sh" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/test_ss_key_rotation.sh --key-added-only" \
    --test "./testscripts/run_regression_continually.sh" 
```

**DO NOT RUN THE GROWTH TEST ON SGX -- IT CANNOT EXECUTE THERE.**  Both halves of it are
debug-only and are refused when `--realenclave` is set:

| command | driven by | on real SGX |
|---|---|---|
| `update-ss-interval-key` | `test_ss_key_rotation.sh` | refused -- `SKIPPED: the enclave refused a forced key rotation` |
| `audit-ss-keys` | `test_ss_reshare_audit.sh` | refused -- `SKIPPED: this is a real SGX enclave` |

So every `--test` entry in the schedule above is a NO-OP on SGX.  The run finishes green
having exercised none of the SS machinery it appears to test.  The suites skip loudly and
say what was lost -- that part is working -- but the SCHEDULE is the lie: it reads like the
M1-M4 growth test and is an empty shell here.  Observed 2026-08-30, eight scheduled tests,
eight skips.

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

So schedule the soak and nothing else.  The empty-schedule trap still applies -- a bringup
with no `--test` at all also skips `wait_addressable` -- so keep exactly one:

```sh
./testscripts/fleet_bringup_with_tests.sh \
  --primary alvillarica@192.168.86.120 \
  --joiner alvillarica@192.168.86.140 \
    --test "./testscripts/run_regression_continually.sh" \
  --block-sync
```

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
G  join each joiner: nth_node_bringup --from 1 --until 7, then wait until
   addressable, then its --test commands
```

`--from <stage>` resumes.  Two things it does **not** do:

- **It skips the genesis wipe.**  A resumed run is not a clean-chain run, so it is
  not a growth test any more -- the keys you measure were minted on the previous chain.
- **It cannot re-join a joiner.**  `add_full_node.sh` refuses a pioneer name the chain
  has already seen, so resuming into stage G after a partial join needs a fresh
  `--pioneer-prefix`, or that node bonded by hand.

---

## Traps this has already hit

**Joiners must be bonded, phase 6.**  It is tempting to join `--from 1 --until 5` and
stop there, because converting re-splits stake -- the old bringup did exactly that.  For
a growth test it is wrong: a node that is not a validator never proposes a block,
`updateIsValidator`
publishes an external address **only under `IsProposer`**, so an unbonded joiner never
becomes addressable, never becomes an SS key owner, and every audit stays quiescent --
the suite goes green having healed nothing.  This script uses `--until 7`.

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
