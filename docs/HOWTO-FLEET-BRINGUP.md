# Bringing up M1-M4, and the re-share growth test

Two scripts bring up a fleet.  They differ in what they are asking.

| | asks | tests |
|---|---|---|
| `testscripts/full_fleet_bringup.sh` | *is this fleet good?* | fixed: full regression, then a soak |
| `testscripts/fleet_bringup_with_tests.sh` | *what happens as the fleet grows?* | **nothing** unless you schedule it |

Both share `testscripts/fleet_lib.sh`, which holds the helpers and the traps.  Read
that and `full_fleet_bringup.sh`'s header before changing either.

---

## The fleet

| name | address | notes |
|---|---|---|
| M1 | `alvillarica@192.168.86.162` | primary |
| M2 | `alvillarica@192.168.86.154` | |
| M3 | `alvillarica@192.168.86.52`  | **.52, not .53** |
| M4 | `alvillarica@192.168.86.136` | |

All aarch64 debug-enclave boxes: no SGX, no ego, ~3 minute builds.

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

**Joiners must be bonded, phase 6.**  `full_fleet_bringup` joins `--from 1 --until 5`
and stops deliberately, because converting re-splits stake.  For a growth test that is
wrong: a node that is not a validator never proposes a block, `updateIsValidator`
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
