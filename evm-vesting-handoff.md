# Handoff: does vesting hold against the EVM? — tested, it holds

Self-contained report. The reader is assumed to have no context from the run.

**Question posed:** on a Cosmos EVM chain the same account has a bech32 and a
`0x` address; vesting locks are enforced in the bank keeper's send path, which
EVM transactions do not use. Can a vesting account move locked tokens through
the EVM?

**Answer: no. Every attempt failed.** The token design proceeds as written — no
change is required on account of the EVM. Roughly 700M QDN of intended locks are
real locks.

The mechanism matters more than the verdict: locked tokens are not *forbidden*
to the EVM, they are *invisible* to it. Every EVM read of an account balance
resolves to the spendable balance. There is therefore no alternate EVM entry
point that could skip a check, because there is no check to skip.

---

## 1. Verdict table

| Test | Path | Result | Evidence |
|---|---|---|---|
| 3 (control) | Cosmos bank send | **BLOCKED** | `spendable balance 0aqdn is smaller than 1000000000000000aqdn: insufficient funds` (sdk, code 5) |
| 4a | Plain EVM transfer | **BLOCKED** | `failed to check sender balance: sender balance < tx cost (0 < 1000020000000000000)` |
| 4b | Bank precompile | **NOT EXERCISED** — no such method, precompile inactive | `active_static_precompiles: []`; v0.5.1 bank precompile is query-only |
| 4c | Vesting precompile | **DOES NOT EXIST** in cosmos/evm v0.5.1 | address constant declared, no implementation |
| 4d | Staking precompile | inactive; **Cosmos-path delegation succeeded, as expected** | delegated 1,000,000 QDN of locked principal, code 0 |
| 4e | Gas payment | succeeds here **only** because this devnet's base fee is ~0 | at a real gas price: `sender balance < tx cost (0 < 21000000000000)` |

No STOP condition in the brief was triggered.

---

## 2. Why it holds — the enforcement chain

There is no ante decorator named for vesting anywhere in the EVM path. Grepping
for one and finding nothing is a false alarm; the enforcement is one layer down
and structural.

```
ante/evm/06_account_verification.go  VerifyAccountBalance -> statedb.Account.Balance
ante/evm/07_can_transfer.go          CanTransfer          -> statedb.Account.Balance
x/vm/keeper/statedb.go:33            acct.Balance = k.SpendableCoin(ctx, addr)
x/vm/keeper/keeper.go:328            SpendableCoin -> bankWrapper.SpendableCoin
x/precisebank/keeper/view.go:58      -> bk.SpendableCoin
                                        comment: "x/bank for integer balance - excluding locked"
x/bank                               SpendableCoins = balance - LockedCoins
```

`statedb.go:33` is the load-bearing line. `GetAccount` — the sole path by which
the EVM StateDB learns any account's balance — overwrites `acct.Balance` with
`SpendableCoin`. The ante pre-checks and the in-EVM transfer both read that
field.

---

## 3. Empirical confirmation

Code reading alone would not settle this. It was confirmed on a live chain.

**Setup.** Key `founder-test` created with `--algo eth_secp256k1`, pubkey type
`/cosmos.evm.crypto.v1.ethsecp256k1.PubKey` — this matters, a standard
secp256k1 Cosmos key derives differently and would produce a false negative.

```
bech32: qadena17chcwt37htv8vv4x6s75c4v8w6raaywefcvu9m
0x:     0xF62f872e3Ebad87632a6D43d4c55877687dE91d9
```

`qadenad debug addr 0xF62f…91d9` round-trips to the same bech32 — one account,
two addresses. `PeriodicVestingAccount`, 29,166,666.67 QDN original vesting,
start 2026-08-22, first period 31,536,000s, so the whole allocation is locked
for a year. At creation: total `29166666666666666666666666 aqdn`, spendable `0`.

**The EVM reports spendable, not total.** After the account received exactly
1 QDN from outside:

```
cosmos total     : 29166667666666666666666666
cosmos spendable :          1000000000000000000
cast balance     :          1000000000000000000   <- tracks spendable
```

**The boundary is exact — not a blanket failure.** This is the part that makes
the result trustworthy:

| Attempt | Value | Outcome |
|---|---|---|
| within spendable | 0.5 QDN | **succeeded**, block 276, status 1 |
| above spendable, far below total | 100 QDN | rejected: `1000000000000000000 < 100000020000000000000` |
| entire locked balance | 28,166,666.67 QDN | rejected: `0 < 28166666666666666666666666` |

The rejection compares against spendable in both cases. The account is not
frozen; it is precisely limited to what has vested.

**Positive control.** A separate funded `eth_secp256k1` account sent 1 QDN over
the EVM successfully (block 255, status 1, gasUsed 21000). The founder's
failures are the lock, not a broken EVM or a misconfigured RPC.

**On 4b's apparent success.** The brief's
`send(address,address,uint256)` call to `0x…0804` returned status 1, block 324,
gasUsed 150000. **This is not a leak.** The precompile is inactive, so the call
was a value-0 call to a codeless address — a no-op. Balances before and after
account fully for gas plus the legitimate 0.5 QDN transfer; the locked
principal was untouched. Anyone re-running this should expect that status 1 and
not misread it.

---

## 4. Environment

- Vesting module: vanilla `cosmos-sdk/x/auth/vesting`, `PeriodicVestingAccount`.
  **Not** an Evmos-lineage clawback module.
- Cosmos EVM: **v0.5.1**. `go-ethereum` replaced by `cosmos/go-ethereum v1.16.2-cosmos-1`.
- EVM-path ante decorator checking vesting: **none by name**; enforcement via
  `SpendableCoin` as traced in §2.
- `cast balance` reports **spendable**.
- Chain: local devnet `qadena_4444-1`, eth chainId `0x115c` (4444), qadenad
  1.1.10, macOS. Feemarket `base_fee = 0.000000000000000261`,
  `min_gas_price = 0` — gas is effectively free, which matters for 4e.
- No mainnet command was run. Throwaway keys, `--keyring-backend test`.

---

## 5. Separate findings — these need a decision, the vesting verdict does not

**5.1 Staking rewards on locked stake are fully liquid.** Expected under vanilla
vesting rules, but it should be stated explicitly in the token design rather
than discovered later. Delegating 1,000,000 QDN of locked principal accrued
115.27 QDN in roughly 20 blocks; after `withdraw-rewards`, spendable went
0.5 → 169.19 QDN, the EVM saw it immediately, and 100 QDN of it was moved out
over the EVM (block 392, status 1). Locked principal stayed locked —
`delegated_vesting` tracked the full 1M correctly — but the yield on it did not.
A founder can therefore draw a real income stream from locked tokens during the
cliff. That may well be intended; it should be intended on purpose.

**5.2 A fully-locked founder cannot pay EVM gas on a chain with a real base fee.**
This devnet's base fee is ~0, so the account can transact. At any real gas
price it is frozen out entirely: `sender balance < tx cost (0 < 21000000000000)`.
On a production fee market a founder would be unable to transact on the EVM
side for the entire cliff without a small unlocked float or a standing feegrant.
Usability, not security — but it will surface as a support burden on day one.

**5.3 The Cosmos bank send is gated by AML before vesting is ever consulted.**
With fees covered by a feegrant so the send handler was actually reached,
`founder -> victim` failed with qadena code 1159: *"This transfer cannot be
AML-scanned; each party must be a wallet with eKYC data or on the
scanned-contract whitelist"*. Meanwhile `treasury -> victim` succeeded, and EVM
transfers between the same two unKYC'd accounts succeeded. So the AML gate
applies to the Cosmos bank path but not the EVM transfer path. This does not
affect the vesting conclusion — the EVM lock is enforced independently, per §2 —
but the asymmetry is unexplained and looks worth its own investigation.

---

## 6. What was NOT tested — do not read the verdict as broader than this

1. **Precompiles were never exercised as live attack paths.** All of
   `active_static_precompiles` is empty on this chain. 4b/4c/4d prove only that
   the surface is currently absent, not that it would be safe if enabled. If
   precompiles are ever activated, **this test must be redone.** Note that
   `DefaultStaticPrecompiles` *are* registered in the keeper
   (`app/non_dependency_inject.go:274`); only the param gates activation, so
   turning them on is a param change away.
2. **ERC-20 / werc20 dynamic precompiles.** Not tested. Reading the source,
   `precompiles/erc20/query.go:175` and `precompiles/werc20/tx.go:71` also use
   `SpendableCoin`, which is a good sign — but that is a code read, not a test.
3. **Only `PeriodicVestingAccount` was covered.** `ContinuousVestingAccount`,
   `DelayedVestingAccount` and `PermanentLockedAccount` were not tested. They
   share the `LockedCoins` mechanism so the result should carry, untested.
4. **Undelegate-then-spend was not tested.** After delegating locked principal,
   `delegated_vesting` was tracked correctly — but whether unbonding returns
   those tokens as *locked* was not verified. Vanilla vesting is designed to,
   and this is the single most valuable follow-up: it is the one remaining path
   by which locked principal could plausibly become spendable early. **Recommend
   testing this next.**
5. **Contract-mediated withdrawal.** No contract was deployed to pull funds. Any
   such path routes through the same `CanTransfer`/StateDB balance, so it should
   be covered by §2, but it was not exercised.
6. Single run, single chain, single vesting schedule.

---

## 7. Deviations from the brief

- Tested against the already-running local devnet `qadena_4444-1` instead of
  initializing a fresh `qadena-dev-1`, as instructed. Local empty devnet; no
  mainnet chain-id was used at any point.
- Funder was `treasury`, not `val` — that is what this devnet has.
- Added three things the brief did not specify: a feegrant from treasury, so
  the control test could reach the send handler rather than stopping at fee
  deduction; a positive control; and the exact-boundary tests in §3. Each was
  added to make a negative result interpretable.
- Nothing was changed to make a test pass. No chain code was modified. Per the
  brief, nothing found here was fixed.

---

## 8. Provenance

| What | Reference |
|---|---|
| Vesting account created | `1954C789F66CB69B6E4F78CB277CEE04EE468A092E4865A0E7A2716E78487390`, height 142, code 0 |
| Control send, own fees | `71B3C8A9C14B97E8CC14B10FD29FE22388DE9F6DA6632BCE5EC4D820DF446160`, code 5 |
| Control send, feegranted | `B11F0DAE00F3FEC1A762731D77E9B0635F41E7986F90A4A467EC231B19A6A2A9`, height 189, code 1 (AML 1159) |
| Positive control, EVM | `0x77a5e093c23618eb280a720ecb9b0cf21bc5bb4a28a462476f5e69485bd9652f`, block 255 |
| Within-spendable transfer | `0x91c726ae6dc0fb5f37c57603c7e406370dcf277c6a9cea6116bf5c7a2e6922c5`, block 276 |
| Bank precompile no-op | `0x827ffc2a134033301832424f8ad6e758a18aed76154efaa711a2f5af5f445dc6`, block 324 |
| Delegation of locked principal | `E332B86C521B8B075528321BB966BB8303E188557248B6BC544EEED20B720B19`, height 354, code 0 |
| Reward withdrawal | `F18698FF1E3F8AF3557EF331B2710191E976FF3AC77236A065934D106EACFFA5`, height 376, code 0 |
| Reward funds moved over EVM | `0x59c6ea7d0677f91f4cc5628b96d97e4a159b22a92552250315f77a9a6a7eff92`, block 392 |

Final founder state: total `28166666666666666666666666 aqdn`, spendable `0`,
delegated `1000000000000000000000000 aqdn`.
