# Bringing up VERITAS — the SEC team's procedure

What **SEC** runs to stand up VERITAS on a Qadena launch chain. Three commands, with the Qadena
Foundation (QFI) acting between them.

The counterpart is [HOWTO-SPONSOR-VERITAS.md](HOWTO-SPONSOR-VERITAS.md), which is QFI's half. They
are separate documents because the two sides never run each other's commands and neither holds the
other's keys — that separation is the point of the whole structure.

> **You never receive tokens.** In the default *foundation-sponsored* model, QFI pays for
> everything by fee grant. There is no SEC treasury, no transfer to wait for, and your admin key
> holds **exactly zero, permanently**. That is the design working, not a state to fix.

---

## The three commands

```sh
# QFI's prepare stage prints this first command with the two addresses already filled in --
# paste what they send you rather than retyping it.
veritas_scripts/step_1.sh --count 30 \
    --appsvr qadena1...   \
    --users  qadena1...
#   -> gives QFI your ADMIN ADDRESS and the PRE-GRANT BLOCK
#   ... QFI runs sec_veritas_after_step_1.sh, tells you when it is done

veritas_scripts/step_2.sh                      # -> gives QFI TWO PROPOSAL IDS
#   ... QFI deposits and votes; wait for both proposals to PASS

veritas_scripts/step_3.sh                      # -> gives QFI a PASTE BLOCK for the sponsor pool
```

**No exports.** Everything each step needs it either takes as an argument or reads from the run's
own file (`$VERITAS_SEC_HOME/variables.json`, written by step_1). In particular step_2 and step_3
find the admin key themselves and use the delegation only after **verifying the grant exists on
chain** -- so a step cannot silently sign the wrong way because someone forgot a variable.

Options shared by all three: `--node <rpc>` (default `tcp://localhost:26657`; the chain-id is then
derived from that node, never trusted from a local file) and `--sec-home <dir>` (default
`~/sec-veritas`).

`--count` is **required** on step_1 and has no default: it sizes the pre-grants (`4*(n+1)`), the
sponsor pool (`n+1`) and the per-wallet split. Use a small number (`--count 3`) for a rehearsal.

Everything else is QFI's.

---

## Who does what, and in what order

| # | who | action | hands over |
|---|---|---|---|
| 1 | QFI | stake, create and fund two sponsor accounts | their two addresses, the chain-id |
| 2 | **SEC** | **`step_1.sh`** | your **admin address** |
| 3 | QFI | delegate `MsgGrantAllowance` authority to it | — |
| 4 | **SEC** | **`step_2.sh`** | **two proposal ids** |
| 5 | QFI | deposit + vote on both | — |
| 6 | both | wait for both proposals to reach **PASSED** | — |
| 7 | **SEC** | **`step_3.sh`** | the **sponsor pool**, as a paste block |
| 8 | QFI | authorise that pool | confirmation |

Neither side can skip ahead. Step 2 blocks until QFI has funded their sponsor account; step 3
cannot run until the two proposals have passed.

---

## Before you start

- **A Qadena node** you can reach, synced to the launch chain.
- **The chain-id**, from QFI.
- **`jq`**.
- **`QADENA_KEYRING_BACKEND=file`.** The steps default to this — an *encrypted* keyring. If you
  see the warning below, you or your environment asked for the unencrypted one:

  ```
  ** keyring-backend is 'test' -- an UNENCRYPTED keyring, plaintext on disk.
  ```

  Fine for a devnet. For a real deployment, stop and re-run with `file`. Keys already created
  under `test` **do not move** by changing the variable.

### Your working directory

Everything this run produces lives in one place — `$VERITAS_SEC_HOME`, default `~/sec-veritas`,
created mode 700:

```
~/sec-veritas/
  variables.json        the run's configuration: names, counts, amounts, fund mode
  mnemonics.json        THE KEYS.  Plaintext, mode 600.
  pool_addresses.json   written by step_3, handed to QFI
```

Steps 2 and 3 read `variables.json` and `mnemonics.json` from here, so all three steps must agree
on it. Export `VERITAS_SEC_HOME` once, or pass `--sec-home <dir>` to step_1.

> **`mnemonics.json` is the one artifact whose loss is unrecoverable and whose disclosure is
> total.** It holds every mnemonic this run creates, in the clear, because steps 2 and 3 read them
> back. Back it up off this machine before you continue, and delete it once the deployment is
> established. Mode 600 inside a 700 directory is the only protection it has.

---

## Step 1 — create your keys

```sh
veritas_scripts/step_1.sh
```

Creates, from freshly generated mnemonics:

| name | what it is |
|---|---|
| `sec-veritas-admin` | **the one QFI needs.** Signs `authz MsgExec`; holds zero forever |
| `secidentitysrvprv` | identity service provider |
| `secdsvssrvprv` | DSVS service provider |
| `sec-create-wallet-sponsor` | the create-wallet sponsor, base of the pool |
| `secdsvs` | the DSVS user |

Then writes `variables.json` and `mnemonics.json`, and ends with:

```
SEND THIS ONE ADDRESS TO QFI:
    sec-veritas-admin : qadena1...
```

...followed by the **pre-grant block**: every wallet address this deployment will ever create,
derived offline from your mnemonics before anything exists on chain. QFI signs a narrow allowance
for each one, which is what lets your wallets be born without a QFI key ever touching your machine.

**Send QFI that address and the block, and nothing else.** Not a mnemonic, not `mnemonics.json`,
not the provider keys.

Useful flags: `--count <n>` (**required**, no default), `--appsvr` / `--users` (QFI's two sponsor
addresses, from their prepare stage), `--node <rpc>`, `--pioneer <name>` (derived from the chain
when omitted -- pass it only if the chain has several), `--sec-home <dir>`, and
`--<name>name` / `--<name>mnemonic` overrides for each key above.
`--fund-mode banksend` restores the retired model where SEC holds a funded treasury; you almost
certainly do not want it.

### What `sec-veritas-admin` is for

A wallet on a toll-free chain cannot pay its own fees — it cannot even claim its credential — so
every wallet you create needs a fee grant. **A fee grant is signed by its granter**, which must be
QFI, and you cannot hold a QFI key.

`authz` resolves it: QFI authorises this key to send `MsgGrantAllowance` *on their behalf*, you
wrap each grant in a `MsgExec` signed by **your** key, and QFI fee-grants that `MsgExec` so the key
never needs a balance. Their money moves, your key authorises, and no QFI private key ever reaches
your machine.

---

## Step 2 — create the service providers

```sh
veritas_scripts/step_2.sh
```

**Nothing to export.** step_2 reads the admin's key name from `variables.json` and then checks the
chain for QFI's authz grant to it. It announces which path it took, in one line:

```
delegated signing: sec-veritas-admin (authz from the sponsor verified on chain)
```

If instead it says `no delegation on chain`, QFI has not run `sec_veritas_after_step_1.sh` yet (or
ran it against a different sponsor) -- stop and tell them, because everything after this point
depends on that grant. The direct-signing fallback exists only for the single-keyring devnet
harness and cannot work on your machine.

The script waits for QFI's sponsor account to be funded, then registers both providers and submits
a governance proposal for each. It ends with:

```
Send the following information to QFI
secidentitysrvprv proposal_id: 12
secdsvssrvprv proposal_id: 13
```

**Send QFI both ids.** They deposit and vote. Watch them yourself:

```sh
provider_scripts/query_service_provider_proposal.sh 12 --wait
```

On a launch chain with the real governance clock this is **6 hours** expedited, or 72 hours if the
expedited track fails and it falls back. On a testnet built with `--test-gov-timings` it is about
30 seconds. Plan the handoff around that — it is the step where a bring-up waits.

### If step_2 seems to hang

It prints `Waiting for funds in <account>` on a loop, with no timeout. That means QFI's sponsor
account has no balance yet. Ask them to confirm their `sec_veritas_before_step_1.sh` run completed
— it verifies its own work against the chain and prints the balances it left.

---

## Step 3 — create the wallets and users

Only after **both** proposals show `PASSED`.

```sh
veritas_scripts/step_3.sh
```

Creates the create-wallet sponsor and the DSVS user, each with `count` ephemeral wallets, and
grants every one of them the user message set — issued as `MsgExec` signed by your admin key,
drawn on QFI's account.

It ends with a **paste block**:

```
SEND THIS BLOCK TO QFI -- they paste it into a terminal as-is:

cat > /tmp/veritas-pool.json <<'POOLEOF'
{ "chain_id": "...", "sponsor_base": "...", "count": 30, "pool": [ ... ] }
POOLEOF
foundation_scripts/sec_veritas_after_step_3.sh --pool-addresses /tmp/veritas-pool.json
```

Send that block. It is one paste on their side: it recreates the file and runs the command.

**Why they need it.** QFI's last action grants each pool wallet the right to issue fee grants as
their account — two transactions per wallet, both signed by them, so only they can send them. They
need every pool member's **address**, and cannot derive them: the ephemerals are HD derivations of
your sponsor's mnemonic, so deriving them means holding a key you must never share.

The block carries the chain-id and the count so their script **verifies** rather than trusts it — a
stale, short or mangled block is refused outright rather than half-applied. A partly-authorised
pool would break onboarding for *some* citizens and not others.

---

## What you send, and what you never send

| step | send |
|---|---|
| after `step_1.sh` | one address — `sec-veritas-admin` |
| after `step_2.sh` | two proposal ids |
| after `step_3.sh` | the pool paste block |

**Never send:** a mnemonic, `mnemonics.json`, a private key, or the contents of your keyring. QFI
never needs any of them, and no step asks for them.

---

---

## Verifying the result

Either side can check the whole deployment against the chain at any time. It is **read-only** --
no keyring, no passphrase, no transactions:

```sh
V=$VERITAS_SEC_HOME                     # or ~/sec-veritas
foundation_scripts/sec_veritas_verify.sh \
    --pregrant $V/pregrant_addresses.json \
    --pool     $V/pool_addresses.json \
    --appsvr $(jq -r .appsvraddr $V/variables.json) \
    --users  $(jq -r .usersaddr  $V/variables.json)
```

The two sponsor addresses come straight out of `variables.json` -- step_1 recorded them there from
QFI's `--appsvr` / `--users` arguments, so you never need to ask for them again.

The files are optional: with only `--appsvr` and `--users` the script reads the wallet set from the
chain instead. Pass them when you have them -- the chain-only form checks what exists, while the
files check it against what was *supposed* to exist, which is the only way to notice a wallet that
was never granted at all. QFI runs the chain-only form, having no access to your directory.

`--pool` is optional -- omit it before step_3 has run. `--node <rpc>` points at a remote chain.
Exit 0 means every check passed; otherwise each failure is named.

What it asserts, and why each one matters:

| check | what a failure means |
|---|---|
| admin balance is **exactly 0** | someone funded the delegation key. It signs hundreds of transactions and must never hold value; investigate, then sweep |
| admin authz is **exactly three** message types | fewer breaks the flow; **more** is worse -- `GenericAuthorization` is uncapped, so every extra type is unreviewed drainage surface |
| admin feegrant is scoped to `MsgExec` **only** | a wider allowance lets the admin spend foundation fees on anything |
| every wallet holds the operational allowance | a narrow or missing one is a wallet that dies on its first real transaction |
| pool wallets hold **both** halves | the app-server picks pool members arbitrarily, so one missing half fails onboarding for *some* citizens and not others |
| **no stray authz grantees** | the only check that proves nothing exists *beyond* the specification -- an unexpected grantee is standing permission to spend a foundation account |
| both providers registered | governance did not complete |

## What can stop you

| symptom | cause |
|---|---|
| `keyring-backend is 'test'` warning | unencrypted keyring — fine on a devnet, wrong for a real deployment |
| `$VERITAS_SEC_HOME/variables.json is missing` | step_1 has not run, or the steps disagree on the directory |
| `Waiting for funds` forever | QFI's sponsor account is unfunded; their before_step_1 has not completed |
| `spendable balance 0aqdn` | a transaction did not **name** its grant. Check the tx's `fee.granter` before you suspect the grant itself — this is the most common failure in this flow |
| code **1159** | recipient is neither a Qadena wallet nor whitelisted. Fee grants are not bank sends and do not need the exemption |
| proposals never pass | QFI's bucket is not bonded enough to carry an expedited vote; their prepare step recomputes and tops up |

---

## Status of this procedure

**The delegated path has been run end to end** (testnet `qadena_4824-1`, 2026-09-06) -- the first
time it has existed at all: before this, `step_1.sh` never created an admin key, so every earlier
run took the direct-signing branch. One bring-up completed all seven steps, and
`sec_veritas_verify.sh` reports 7/7 against the chain: admin balance exactly 0 after 200+ signed
transactions, three delegated authorities and no strays, every wallet widened, the pool authorised
both ways, both providers registered by governance.

What that run **did not** prove, stated plainly:

- **Fee economics.** The testnet's feemarket floored near zero, so transactions were effectively
  free. The grant *mechanics* were exercised on every transaction -- each named its granter and the
  chain resolved the allowance -- but not the *cost*. The per-user figures in the sponsor HOWTO come
  from measurements at real gas prices, not from this run.
- **The app-server's own path.** Everything here is the CLI. The server broadcasts citizen
  onboarding itself, and a defect in that path was found by code review during this bring-up (the
  create-wallet grant is issued from `foundation-users` but the transaction names the *pool wallet*
  as fee granter, and grants do not chain). Onboarding one citizen through the server is the
  decisive test, and it has not been run.
- **Recovery and rotation.** `MsgSignRecoverPrivateKey` and `MsgRemoveCredential` are in the
  wallets' allowance but were never exercised.

Two things this run fixed that are worth knowing if you read older notes:

- The widen now grants the **union** of the operational and user message sets. Previously the two
  overwrote each other -- a grantee holds one allowance per granter -- so the end state silently
  dropped every claim, rotation and bind message, and the bring-up's own claims passed only because
  they ran between the two grants.
- `create_user.sh`'s granter was long suspected wrong. It is correct: in sponsored mode the treasury
  argument *is* the foundation's appsvr account, so the grant comes from the foundation, as intended.
