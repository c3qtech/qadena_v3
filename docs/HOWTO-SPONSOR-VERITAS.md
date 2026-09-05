# Sponsoring VERITAS — the Qadena Foundation's procedure

What the **foundation** does to bring up the SEC PH VERITAS deployment on a launch chain.

This is the counterpart to the SEC group's `veritas_scripts/step_1.sh`, `step_2.sh` and `step_3.sh`.
It is deliberately a separate document, because the two sides never run each other's commands and
neither holds the other's keys — that separation is the point of the whole structure, and a single
runbook covering both would obscure it.

> **This is not `testscripts/setup_veritas.sh`.** That script is a test harness: it plays both roles
> at once, holds every key in one keyring, and funds everything with `tx bank send --from treasury`
> because on the devnet `treasury` is a single key the primary holds. **On a launch chain no such
> key exists.** Every bucket is an N-of-M multisig whose members are on separate machines by design,
> so each foundation spend below is a ceremony, not a transaction.

---

## Who does what, and in what order

The two sides alternate. Neither can proceed without the other's previous output.

| # | who | action | hands over |
|---|---|---|---|
| 1 | **FOUNDATION** | `sponsor_veritas.sh --stage prepare` | `foundation-veritas-appsvr` + `foundation-veritas-users` addresses, chain-id |
| 2 | SEC | `step_1.sh` | SEC's **admin address** |
| 3 | **FOUNDATION** | `veritas_sec_delegate_grant_authority.sh --sec-admin <addr>` | — |
| 4 | SEC | `step_2.sh` | **two proposal ids** |
| 5 | **FOUNDATION** | `sponsor_veritas.sh --stage approve <id> <id>` | — |
| 6 | both | wait for both proposals to reach **PASSED** | — |
| 7 | SEC | `step_3.sh` | — |
| 8 | **FOUNDATION** | `veritas_sec_authorise_pool.sh` | the two sponsor addresses, confirmed |

All four foundation actions live in `foundation_scripts/`, and none of SEC's do. The two that sit
*between* SEC's steps are named as a pair -- `veritas_sec_delegate_grant_authority.sh` (delegate authority to
SEC's admin) and `veritas_sec_authorise_pool.sh` (authorise the app-server's sponsor pool) -- so the
directory listing says who runs what, which the old `step_4.sh` name did not.

**Why the foundation must run 3, 5 and 8 rather than delegating them.** A fee grant is signed by its
*granter*, and `authz` cannot be sub-delegated. So even with the step 3 authorisation, SEC cannot
issue grants *as* the foundation for the app-server's pool. Moving steps 3, 5 or 8 into SEC's scripts
would put a foundation private key on a SEC machine — the one thing this structure exists to prevent.

---

## Before you start

- **A launch chain**, built and producing blocks. See
  [HOWTO-LAUNCH-CHAIN-BRINGUP.md](HOWTO-LAUNCH-CHAIN-BRINGUP.md).
- **The bucket multisigs exist in your keyring**, along with enough member keys to meet each
  threshold. `foundation_scripts/derive_launch_keys.sh` creates them.
- **`jq` and `python3`.**
- **The chain-id**, if `qadenad status` cannot reach a node: `export QADENA_CHAIN_ID=qadena_482-1`.

### Which buckets pay, and why it is not a choice

`tokenomics/allocations.csv` is the authority (HARD RULE 1) and it already names them:

| bucket | account | role here | custody | stakes |
|---|---|---|---|---|
| 10 Public Sector Programs | `pubsec` | funds the two sponsor accounts | **5-of-7** | no |
| 03 Foundation Treasury | `foundation` | deposit + vote on the proposals | 3-of-5 | **yes** |

Bucket 10's own notes read *"Sub-allocations: **SEC PH VERITAS 60M**; future MOUs; OTC swap reserve.
Entities only, never individuals. **Funds feegrant sponsor account**"*, and its `permanent_home`
column names `foundation-veritas-appsvr`/`foundation-veritas-users` outright. Bucket 03 is the **only** bucket with
`stakes = yes`, so voting power can come from nowhere else — pubsec could fund the deployment but
could never vote it through.

Funding VERITAS out of Adoption or Node Operations would spend an allocation earmarked for something
else, against the file everyone reconciles against later. Override only with a decision recorded
somewhere: `--fund-bucket` / `--stake-bucket`.

---

## Step 1 — prepare (before SEC's `step_1.sh`)

```sh
foundation_scripts/sponsor_veritas.sh --stage prepare \
    --pubsec-members pubsec-m1,pubsec-m2,pubsec-m3,pubsec-m4,pubsec-m5 \
    --members        foundation-m1,foundation-m2,foundation-m3
```

Three things happen:

1. **Creates `foundation-veritas-appsvr` and `foundation-veritas-users`** if they do not exist, as ordinary
   `eth_secp256k1` keys — not multisigs. They are the *granter of record* for fee grants and must be
   able to sign alone. Existing keys are reused, never re-minted: their addresses are what SSM and
   the deployment's `.env` already point at.
2. **Funds each with 100,000 QDN from `pubsec`** (`--amount` to change). Two separate ceremonies.
   `testscripts/setup_veritas.sh` uses 2,000,000 for the same two accounts on the devnet; that
   figure is about fee volume, not endowment. **Top up rather than overfund** -- another transfer
   from `pubsec` is one more ceremony, but getting money back *out* of a sponsor account needs a
   governance proposal, because it is not a wallet and not on the AML whitelist (code 1159).
3. **Delegates from `foundation`** enough to carry an **expedited** vote later.

### Why two sponsor accounts rather than one

They behave differently, and separating them is worth the extra account:

- **`foundation-veritas-appsvr`** — SEC's own operational wallets. A **fixed** set, known at deployment, so
  they are granted directly and once.
- **`foundation-veritas-users`** — citizen wallets. These appear continuously (every onboarding, QR scan and
  key rotation mints one), so the app-server issues their grants at runtime via `authz`. That
  delegation is unbounded by nature; keeping it on a separate account confines it to the user float.

It also makes usage independently observable: appsvr burn tracks SEC's processing, users burn tracks
citizen activity, and a divergence between them is a real anomaly signal.

### How much stake, and why it is computed

An expedited proposal needs `expedited_threshold` (**0.667**) of the votes cast. Voting power follows
**bonded** stake and is credited to the **delegator**, not the validator. If the foundation is the
only voter, its bonded stake must exceed twice everyone else's:

```
self / (self + other) > 2/3    <=>    self > 2 × other
```

The script reads the staking pool, subtracts what `foundation` has already bonded, and delegates the
difference plus a 20% margin — which absorbs a validator joining mid-ceremony. It is computed rather
than hardcoded because the answer changes every time a node joins.

> The arithmetic runs in Python, not the shell. These are **aqdn**: 504M QDN is 5.04×10²⁶, and zsh
> truncates integers past 20 digits — `2 * other * 12` evaluates *negative* at real magnitudes, which
> would silently skip the delegation. HARD RULE 3.

Override with `--stake <qdn>` if you know better, or `--validator <valoper>` to pick the delegate
(default: the largest bonded validator).

**Hand SEC** the two addresses and the chain-id, printed at the end. Then they run `step_1.sh`.

---

## Step 3 — authorise SEC (after their `step_1.sh`)

```sh
foundation_scripts/veritas_sec_delegate_grant_authority.sh \
    --sec-admin <SEC's ADMIN address -- see below> \
    --foundation-appsvr foundation-veritas-appsvr
```

### Which address is "SEC's admin" -- and it is NOT sec-treasury

**Do not use the address `step_1.sh` prints.** That is `sec-treasury`, and it belongs to the
retired *banksend* model. In the sponsored flow nothing uses it: `step_2.sh:53` and `step_3.sh:73`
both repoint `treasuryname` at the foundation account and say so on screen -- *"sec-treasury is not
used"* -- and `veritas_sec_authorise_pool.sh` never mentions a treasury at all. `step_1.sh`'s closing message
("When QFI grants the necessary amount to sec-treasury...") is stale.

The admin is a **different key, defined by holding nothing**:

| property | value |
|---|---|
| balance | **zero, permanently** -- that is the design, not a starting state |
| authz | granted by this step to send `MsgGrantAllowance` **as** the foundation |
| feegrant | granted by this step for `MsgExec`, so it never needs a balance to sign |
| created by | **no script** -- see the gap below |

A zero-balance account can sign because the fee grant covers it; `testscripts/test_toll_free.sh`
exercises exactly this (`fresh_key` creates the key with no funding, and `tx authz exec --from
secadmin --fee-granter foundation-users` then succeeds).

> **GAP -- confirm this with SEC before running the step.** `VERITAS_SEC_ADMIN` is read in three
> places (`scripts/setup_env.sh:412`, `provider_scripts/create_user.sh:68`,
> `veritas_scripts/step_3.sh:37`) and **set by nothing**, and no script creates an admin key.
> `veritas_sec_delegate_grant_authority.sh` ends by telling SEC to `export VERITAS_SEC_ADMIN=<key name>`, assuming such a
> key already exists. The devnet harness never catches this because it holds every key in one
> keyring, so `grant_as_foundation` takes its no-signer branch and the authz path is never
> exercised. **Ask SEC for the address of the key they will sign `MsgExec` with, and do not
> substitute `sec-treasury` for it.** Authorising the wrong address produces a grant nothing uses,
> and `step_3.sh` fails on every wallet it tries to create.

This replaces the old "QFI grants tokens to sec-treasury" handoff. **Nothing is transferred. SEC
holds no tokens at all.** What it receives is a revocable permission to spend the foundation's money
on *fees*, and nothing else.

Concretely, SEC may send `/cosmos.feegrant.v1beta1.MsgGrantAllowance` as the foundation, and have the
foundation pay for those `MsgExec` transactions. It is needed because `step_3.sh` must grant every
wallet it creates — a wallet holds nothing on a toll-free chain and cannot even claim its own
credential without a grant — so without this, step 3 would need a foundation key on a SEC machine.

**Understand what you are signing.** `GenericAuthorization` cannot cap an amount or restrict a
recipient. This is a real trust grant, bounded by three things and no others:

- its **expiry** — one year by default; `--expiration <unix-seconds>` to shorten it,
- the **spend limits SEC puts on the grants it issues**,
- your ability to **revoke it instantly**: `qadenad tx authz revoke <sec-admin>
  /cosmos.feegrant.v1beta1.MsgGrantAllowance --from foundation-veritas-appsvr`.

Shorten the expiry for a pilot. A year is chosen to avoid stranding a production deployment, not
because a year is safe.

---

## Step 5 — approve the proposals (after their `step_2.sh`)

`step_2.sh` prints two proposal ids — one for the identity service provider, one for DSVS.

```sh
foundation_scripts/sponsor_veritas.sh --stage approve 12 13 \
    --members foundation-m1,foundation-m2,foundation-m3
```

Deposits 10,000,000 QDN and votes **yes** on each, from `foundation` — the deposit needs liquid
tokens and the vote needs bonded ones, and bucket 03 is the only bucket with both.

Then watch each to `PASSED` before SEC runs `step_3.sh`:

```sh
provider_scripts/query_service_provider_proposal.sh 12 --wait
provider_scripts/query_service_provider_proposal.sh 13 --wait
```

On a launch chain with the real governance clock this is **6 hours** expedited, 72 hours if the
expedited track fails and it falls back. On a testnet rendered with `--test-gov-timings` it is
about 30 seconds. Plan the handoff accordingly — this is the step where a bring-up waits.

---

## Step 8 — the last foundation action (after their `step_3.sh`)

```sh
foundation_scripts/veritas_sec_authorise_pool.sh \
    --foundation-users  foundation-veritas-users \
    --foundation-appsvr foundation-veritas-appsvr \
    --count 30
```

Authorises the app-server's sponsor pool and returns the two addresses for SEC's configuration.
`--count` is the size of the pool; match it to what SEC used in `step_1.sh`.

---

## The multisig ceremonies

Every bucket spend above is build → sign (once per member) → combine → broadcast. The script drives
all four when the member keys are in your keyring.

**Members on the command line, or interactively.** `--members` / `--pubsec-members` take a
comma-separated list of key names. Omit either and you are prompted, with the bucket's threshold
shown.

**Members on separate machines.** Use `--print-ceremony`. Nothing is signed locally; you get the
exact command each member runs, and you collect the shares. No key, share or mnemonic ever crosses
the wire — only the account number/sequence and the fully signed transaction, which is public by
definition since the next thing that happens to it is broadcast to every validator.

**Two traps the script already handles**, and a hand-rolled ceremony does not:

- **The threshold is per bucket.** `pubsec` is **5-of-7**; most others are 3-of-5. Passing three
  members to a 5-of-7 bucket fails at `combine`, at the *end* of the ceremony.
- **The sequence.** Every signature commits to the bucket's account sequence, and it is written when
  a share is *signed*. Two transactions signed in one sitting both carry the current sequence, so the
  second is invalid the moment the first lands. The script signs consecutive spends at +0, +1, +2 …
  and every share of one transaction must agree on the number.

**If your workstation cannot reach the RPC** — a filtered VPN, or an outbound policy that permits
dynamically-linked binaries while denying Go ones — add `--via-ssh user@node`. Only the chain-touching
reads and the final broadcast run remotely; signing stays local.

---

## What can stop you

| symptom | cause |
|---|---|
| `no key 'pubsec' in this keyring` | you are not on the coordinator host, or `derive_launch_keys.sh` has not run |
| `combine` fails after every member signed | too few members for the threshold — `pubsec` is 5-of-7 |
| a spend broadcasts, the next fails | sequence collision; the script handles this, a manual ceremony must pass `--sequence-offset` |
| code **1159** on a transfer | the recipient is neither a wallet nor whitelisted. Fee grants are *not* bank sends and do not need the exemption — this is why no `whitelist_bank_send` step appears above |
| proposal never reaches quorum | `foundation` is not bonded enough; re-run `--stage prepare`, which recomputes and tops up |
| `cannot determine the chain-id` | no reachable node; `export QADENA_CHAIN_ID=…` |

---

## What this costs the foundation

| item | amount | from |
|---|---|---|
| `foundation-veritas-appsvr` float | 100,000 QDN | `pubsec` |
| `foundation-veritas-users` float | 100,000 QDN | `pubsec` |
| proposal deposits | 2 × 10,000,000 QDN | `foundation` — **returned** when a proposal passes |
| delegation | computed | `foundation` — **not spent**, and unbondable later |

Against bucket 10's 60M QDN VERITAS sub-allocation, the 200,000 float is the only outlay that leaves
the foundation. Credential issuance is by far the most expensive operation on this chain (measured at
~5.9×10¹⁹ aqdn, against ~3.2×10¹⁴ for a document signature), which is why the sponsor accounts are
sized well above the per-provider amounts SEC's own `step_1.sh` uses.
