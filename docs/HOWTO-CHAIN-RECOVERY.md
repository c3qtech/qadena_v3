# HOWTO: bring the chain back into service after a fork

**Scope.** Resuming the **same chain** at a height all node operators agree on, after nodes
have diverged. Deliberately out of scope: enclave binary upgrades / MRENCLAVE changes
(see `HOWTO-TESTING.md` §7.4), and starting a new chain from exported state.

**Status.** The mechanisms below are read from the code and cited by file:line. The
**end-to-end procedure has not been executed.** Section 7 lists what must be tested before
anyone relies on this in anger. Written after the 2026-08-10 fork; that incident is the
worked example throughout.

---

## 1. Why this is not a stock Cosmos rollback

On a stock SDK chain the app hash is a pure function of the blocks, so rewinding state and
replaying is safe. **Not here.** `EnclaveEndBlock` copies state *out of* the enclave into the
chain store, and the sync calls are destructive drains —
`MsgSyncWallets{Clear: true}`, `MsgSyncCredentials{Clear: true}`, and so on
(`x/qadena/keeper/enclave_grpc_client.go:788` onward; the source comment reads "drains the
enclave's pending credential changes").

So the app hash depends on enclave state that is not derivable from the block alone, and the
enclave has no rollback of its own. Any rewind must answer: **how does each node's enclave get
back to a state consistent with height H?**

The good news is that there is a mechanism for exactly this, and it runs automatically.

---

## 2. The enclave reconciles itself from the chain at startup

`EnclaveBeginBlock` (`x/qadena/keeper/enclave_grpc_client.go:743`) calls
`enclaveSynchronizeStores` once per process, on the first block after startup, guarded by the
package-level `synchronizedWithEnclave` flag (`:741`).

`enclaveSynchronizeStores` (`:1248`):

1. Calls `GetStoreHash` on the enclave for its per-store hashes.
2. Compares each against the chain's hash for the same prefix (`StoreHashByKVStoreService`).
3. **Where they differ, pushes the chain's records into the enclave.**

The chain is authoritative. Eight stores are covered:

| store | push call |
|---|---|
| `WalletKeyPrefix` | `EnclaveClientSetWallet` |
| `CredentialKeyPrefix` | `EnclaveClientSetCredential` |
| `PublicKeyKeyPrefix` | `EnclaveClientSetPublicKey` |
| `JarRegulatorKeyPrefix` | `EnclaveClientSetJarRegulator` |
| `IntervalPublicKeyIDKeyPrefix` | `EnclaveClientSetIntervalPublicKeyId` |
| `ProtectKeyKeyPrefix` | `EnclaveClientSetProtectKey` |
| `RecoverKeyKeyPrefix` | `EnclaveClientSetRecoverKey` |
| `EnclaveIdentityKeyPrefix` | `EnclaveClientSetEnclaveIdentity` |

**This is what makes an in-place rollback plausible.** Roll the chain back to H, restart, and
the enclave is reconciled to the chain's H-state without any manual enclave surgery.

### 2.1 The gap you must know about

**`enclaveSynchronizeStores` only ever SETS. There is no delete path.**

Each branch iterates `GetAllX(sdkctx)` and calls `EnclaveClientSetX` for every record the
chain holds. Nothing removes a record the *enclave* holds that the chain does not.

Consequence: if rolling back to H **unwinds record creations** — a wallet, credential,
protect key or interval key created between H and the fork tip — those records stay in the
enclave as orphans. The store hashes will still differ after the push, the node will log
`OUT-OF-SYNC` on every startup, and it will not converge on its own.

This is the single most important thing to test (§7). It does not affect *value* changes to
existing records, which the set-push does fix; only net-new records that the rollback removes.

Note also that the enclave's **secret** material (private keys, sealed in `enclave_data/`) is
not in any chain store and is untouched by rollback. That is normally fine — key material is
cumulative, and an enclave holding a key the chain no longer references is harmless — but it
is why `enclave_data/` cannot be reconstructed from chain state if it is ever lost. It is
sealed to a machine-bound SGX key and cannot be copied between machines.

---

## 3. Step 1 — agree on the height H

H is the **last block every node executed identically**.

A header's `AppHash` is the result of executing the **previous** block. So if nodes disagree
about the app hash in block N's header, the divergence happened executing **N-1**, and
`H = N - 2` is the last height known-good on every node.

In the 2026-08-10 incident: nodes disagreed on the AppHash in block 61,068's header, so the
divergence was in executing 61,067, and the last commonly-agreed executed block was 61,066.
Note that both nodes still *committed* block 61,067 — they just committed it with different
resulting state. Choosing H is a decision about which executed state everyone accepts, and
picking H = 61,066 discards the disputed execution entirely.

```bash
# compare a header's app hash across all nodes
for h in <node1> <node2> ...; do
  echo -n "$h: "
  ssh $h 'curl -s "localhost:26657/block?height=<N>" \
    | python3 -c "import json,sys;print(json.load(sys.stdin)[\"result\"][\"block\"][\"header\"][\"app_hash\"])"'
done
```

Walk N backwards until every node reports the same hash. **Do not assume the
highest-stake node is correct** — stake decides which fork survives, not which is right. In
the 2026-08-10 incident the 99%-stake node was the corrupt one.

Record H, its block time, and the agreed AppHash somewhere all operators can see. Every node
must roll back to the *same* H.

---

## 4. Step 2 — freeze and archive, on every node

```bash
sudo <repo>/scripts/stop_qadena.sh --all      # sudo required when a real enclave is running
```

Then archive **outside `$QADENAHOME`**, because the recovery scripts delete
`$QADENAHOME/{config,data,keyring-test,enclave_config,enclave_data}`:

```bash
A=~/qadena-archive-$(date +%Y%m%d)
mkdir -p $A
for d in config data enclave_config enclave_data keyring-test; do sudo cp -a ~/qadena/$d $A/; done
sudo tar -c -C ~/qadena logs | gzip -1 > $A/logs.tar.gz
sudo chown -R $USER:$USER $A
```

Verify the copy rather than trusting it — compare `find -type f | wc -l` and `du -sb` against
the source for each directory, and `gzip -t` the tarball.

**The chain is halted from the first `stop_qadena.sh` until every node is back.** Plan the
window. A node holding >1/3 of stake being away is enough to prevent commits.

---

## 5. Step 3 — roll each node back to H

`qadenad rollback` is registered via `evmserver.AddCommands` → `sdkserver.NewRollbackCmd`
(`vendor/github.com/cosmos/evm/server/util.go:54`). The node must be stopped.

The two halves have very different capabilities:

| half | granularity |
|---|---|
| app store — `RollbackToVersion(target)` → IAVL `LoadVersionForOverwriting` (`vendor/cosmossdk.io/store/rootmulti/store.go:1074`) | **arbitrary height, one call** |
| CometBFT — `state.Rollback(bs, ss, removeBlock)` (`vendor/github.com/cometbft/cometbft/state/rollback.go:15`) | **exactly one block**, no height parameter, `bs.DeleteLatestBlock()` |

So the shipped command unwinds **one block per invocation**, gated by the CometBFT half.

**Use `--hard`.** Without it the block is left in the blockstore and replayed on restart —
which for fork recovery means re-executing the very block you are trying to discard. `--hard`
also deletes it.

```bash
# roll back from current height to H
H=<agreed height>
while true; do
  cur=$(<binary> ... )   # read blockstore height
  [ "$cur" -le "$H" ] && break
  qadenad rollback --hard --home ~/qadena
done
```

### 5.1 Practicality, and the tool worth building

Each invocation opens the app and its DB. For the 2026-08-10 incident that is
**31,675 invocations** on the corrupt node — impractical.

Since the app-store half is already arbitrary-height, a one-shot command is a small piece of
work and is the right answer for any large rewind:

- open the DB **once**
- loop only the cheap CometBFT half down to H (`DeleteLatestBlock` needs no app)
- call `RollbackToVersion(H)` **once** at the end

Build this before you need it.

### 5.2 Pruning limits how far back you can go

`config/config.yml` sets `pruning: "default"`, which keeps **362,880** versions
(`vendor/cosmossdk.io/store/pruning/types/options.go:65`). `keep-recent`/`interval` are
ignored unless the strategy is `custom`.

H must be within that window. Verify before committing to a plan — if H has been pruned,
`LoadVersionForOverwriting` cannot reach it and rollback is off the table entirely.

---

## 6. Step 4 — restart, and verify convergence

Start every node, then confirm the enclave reconciliation actually converged. Do **not** just
check that heights advance.

```bash
# 1. the enclave must be alive.  it listens on a UNIX SOCKET, not a TCP port --
#    `ss -ltnp | grep 50051` shows nothing even when it is perfectly healthy.
ps -eo pid,etime,args | grep -E "[e]go-host|[q]adenad "
ls -la /tmp/qadena_50051.sock

# 2. chain->enclave reconciliation: expect in-sync, investigate OUT-OF-SYNC
grep -a "enclaveSynchronizeStores" ~/qadena/logs/qadena-$(date +%Y-%m-%d).log

# 3. no enclave errors in the steady state
grep -a "enclave_cmd - E" ~/qadena/logs/qadena-$(date +%Y-%m-%d).log | tail

# 4. app hashes agree across nodes at the same height (see §3)

# 5. the suite that exists for exactly this
./testscripts/test_peer_agreement.sh
```

A persistent `OUT-OF-SYNC` line for a store after startup is the §2.1 gap biting. Do not
continue past it.

> `test_peer_agreement.sh` exits 0 with "NOTHING COMPARED" on a single node. A green result
> there proves nothing — it must run with at least two nodes up.

### 6.1 Double-signing

Every validator rolled back to H will re-sign heights it has already signed. That is
equivocation if anyone still holds the old votes.

> **There is no double-sign protection in this stack. Do not assume one.**
>
> Nodes using a remote signer (`priv_validator_laddr`) leave `data/priv_validator_state.json`
> at height 0 — CometBFT never updates it, so it is not a guard. And the remote signer's own
> guard is **disabled**: in `cmd/signer_enclave/signer_enclave.go` the two `canSign(...)` calls
> (the vote path at :436 and the proposal path at :501) are both inside `/* */` blocks.
> `canSign` (:537) is therefore dead, and so is `loadState` (:253), which only `canSign` calls.
> `saveState` still runs on every vote and proposal, which makes
> `enclave_data/signer_state.json` a **write-only file** — updated constantly, read by nothing.
>
> So a rolled-back validator will re-sign old heights without complaint, and nothing anywhere
> would stop two copies of the same node signing conflicting blocks. The mitigation is entirely
> operational (below), and "restore the archive onto a second machine while the original runs"
> is an unguarded way to get slashed.

- Check the window first: `qadenad q slashing params`.
- In practice the exposure is small once the fork's blocks are gone everywhere: evidence needs
  a node holding the conflicting precommits. Delete the divergent blocks (`--hard`, §5) and
  clear `data/cs.wal/` on every node.
- On a testnet, the alternative is to accept it — evidence is discarded with the old chain.
- If the chain is valuable, roll back with validator keys removed and re-add them after the
  agreed height is past.

---

## 7. What must be tested before trusting this

None of the following is established. Test on a **two-node** setup — a single node cannot
exercise consensus agreement, which is the entire point.

1. **Does the §2.1 no-delete gap actually block convergence?** Create records after H, roll
   back past their creation, restart, and check whether the stores converge or log
   `OUT-OF-SYNC` forever. **This is the one that decides whether in-place rollback is viable
   at all.** If it blocks, `enclaveSynchronizeStores` needs a delete path — the enclave needs
   a "replace this store wholesale" call rather than per-record sets.
2. **Is transaction replay idempotent against an already-advanced enclave?** After a rollback
   the enclave has already processed the transactions in H+1. Re-executing them may be
   idempotent, may error, or may produce different deltas. With `haltOnEnclaveFailure`
   deployed an error now halts the node rather than corrupting it — so the failure is safe,
   but it is still a failure.
3. **Does a node restart cleanly after `CONSENSUS FAILURE`?** In the 2026-08-10 incident the
   halted node was never restarted — one `starting node` line in its entire log history. The
   reactor died while the process stayed alive. Recovery-by-restart is untested.
4. **The full procedure end-to-end**, with a deliberately forked two-node setup.

Until (1) and (2) are answered, treat in-place rollback as **plausible but unproven**, and
keep archives (§4) as the fallback.

---

## 8. If rollback turns out not to be viable

Fall back to rebuilding rather than fighting the enclave. Both alternatives are out of scope
here by choice, but note which problem each solves: a genesis rebuild discards all state, and
an export-and-restart keeps balances and credentials at the cost of resetting height and
carrying the enclave's sealed keys across separately. Neither needs the reconciliation
machinery above to work.

---

## 9. Traps that cost real time

- **Logs roll at LOCAL midnight; block headers are UTC.** An event stamped Aug 9 UTC lands in
  the Aug **10** log file. This alone hid the 2026-08-10 root cause for a day.
- **The enclave uses a unix domain socket** (`/tmp/qadena_50051.sock`). TCP port checks are
  useless. Check the process.
- **`pgrep -f <pattern>` matches your own ssh command line.** Use
  `ps -eo pid,args | grep "[p]attern"`.
- **A node with a dead enclave still answers RPC and still reports `catching_up: false`.**
  Liveness of the node says nothing about liveness of the enclave.
- **Stake is not correctness.** The node that keeps producing is the one with >2/3, not the
  one that is right.
