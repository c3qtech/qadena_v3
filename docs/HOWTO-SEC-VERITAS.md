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
export VERITAS_SEC_HOME=~/sec-veritas          # where this run's files live
export QADENA_KEYRING_BACKEND=file             # encrypted keyring (the default for these steps)

veritas_scripts/step_1.sh                      # -> gives QFI your ADMIN ADDRESS
#   ... QFI runs sec_veritas_after_step_1.sh, tells you when it is done

export VERITAS_SEC_ADMIN=sec-veritas-admin     # REQUIRED before step_2 (see below)
veritas_scripts/step_2.sh                      # -> gives QFI TWO PROPOSAL IDS
#   ... QFI deposits and votes; wait for both proposals to PASS

veritas_scripts/step_3.sh                      # -> gives QFI a PASTE BLOCK for the sponsor pool
```

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
    export VERITAS_SEC_ADMIN=sec-veritas-admin
```

**Send QFI that address and nothing else.** Not a mnemonic, not `mnemonics.json`, not the provider
keys.

Useful flags: `--count <n>` (ephemeral wallets per user, default **30**), `--pioneer <name>`,
`--sec-home <dir>`, and `--<name>name` / `--<name>mnemonic` overrides for each key above.
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
export VERITAS_SEC_ADMIN=sec-veritas-admin
veritas_scripts/step_2.sh
```

**`VERITAS_SEC_ADMIN` is not optional.** Unset, the scripts fall back to signing grants directly as
the foundation — which works only where one keyring holds both sides' keys, i.e. never on your
machine. Export it before step_2 and keep it exported through step_3.

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

**The delegated `authz` path has not been run end to end.** `testscripts/test_authz_feegrant.sh`
proves the *mechanism* — a genuinely distinct signer, ending at zero balance, and a repeat failing
after revoke — but the devnet harness holds every key in one keyring and never exports
`VERITAS_SEC_ADMIN`, so it has always taken the direct-signing branch instead. The wiring through
steps 1–3 is unproven. Expect to debug it on the first real run, and start from a failing
transaction's `fee.granter`.

One known inconsistency, not yet resolved: `provider_scripts/create_user.sh` sets the grant's
granter to the **sponsor wallet**, while the app-server sets it to QFI's users account. Fee grants
do **not** chain, so the CLI path currently draws on the sponsor's own balance. It passes on the
devnet only because the harness funds that sponsor.
