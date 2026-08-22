# Does vesting hold against the EVM?

**Answer: yes.** Every attempt to move locked funds through the EVM failed. The
lock is enforced because the EVM's entire notion of "balance" is the *spendable*
balance, so locked tokens are invisible to it rather than merely forbidden.

Run: 2026-08-22, local devnet `qadena_4444-1`, qadenad 1.1.10, macOS. No mainnet
command was run. Throwaway keys, `--keyring-backend test`.

## Results

| Test | Path | Result | Error / notes |
|---|---|---|---|
| 3 (control) | Cosmos bank send | **BLOCKED** | `spendable balance 0aqdn is smaller than 1000000000000000aqdn: insufficient funds` (sdk code 5). With fees granted so the send handler was reached, blocked earlier still by Qadena AML, code 1159. |
| 4a | Plain EVM transfer | **BLOCKED** | Estimator: `insufficient funds for transfer`. Forced past it: `failed to check sender balance: sender balance < tx cost (0 < 1000020000000000000)`. |
| 4b | Bank precompile | **N/A — no such method, and not active** | `active_static_precompiles` is `[]`. The v0.5.1 bank precompile is query-only: `balances`, `totalSupply`, `supplyOf`, all `view`. No send/transfer exists to call. |
| 4c | Vesting precompile | **N/A — does not exist in v0.5.1** | Address constant `0x…0803` is declared, but there is no `precompiles/vesting` implementation and no `WithVestingPrecompile` in `DefaultStaticPrecompiles`. |
| 4d | Staking precompile | precompile inactive; **Cosmos-path delegation succeeded, as expected** | Delegated 1,000,000 QDN of locked tokens, code 0. `delegated_vesting` tracked it correctly. Rewards are spendable — see finding below. |
| 4e | Gas payment | **Works here only because this devnet's base fee is ~0** | At gas price 0: succeeds. At any real gas price: `sender balance < tx cost (0 < 21000000000000)`. |

## Setup

`founder-test`, `--algo eth_secp256k1`, pubkey type
`/cosmos.evm.crypto.v1.ethsecp256k1.PubKey`.

```
bech32: qadena17chcwt37htv8vv4x6s75c4v8w6raaywefcvu9m
0x:     0xF62f872e3Ebad87632a6D43d4c55877687dE91d9
```

`qadenad debug addr 0xF62f…91d9` round-trips to the same bech32, so both
addresses are one account.

`PeriodicVestingAccount`, original vesting 29,166,666.67 QDN, start 2026-08-22,
first period 31,536,000s — the entire allocation is locked for a year.
At creation: total `29166666666666666666666666 aqdn`, spendable `0`. No STOP.

## Why it holds

There is no ante decorator named for vesting anywhere in the EVM path. The
enforcement is structural, one layer down, and that is why it cannot be
side-stepped by choosing a different EVM entry point:

```
ante/evm/06_account_verification.go  VerifyAccountBalance -> statedb.Account.Balance
ante/evm/07_can_transfer.go          CanTransfer          -> statedb.Account.Balance
x/vm/keeper/statedb.go:33            acct.Balance = k.SpendableCoin(ctx, addr)
x/vm/keeper/keeper.go:328            -> bankWrapper.SpendableCoin
x/precisebank/keeper/view.go:58      -> bk.SpendableCoin   ("x/bank for integer balance - excluding locked")
x/bank                               -> SpendableCoins = balance - LockedCoins
```

Every EVM read of an account balance resolves to spendable. Confirmed
empirically: after receiving exactly 1 QDN from outside, the founder showed
total `29166667666666666666666666`, spendable `1000000000000000000`, and
`cast balance` returned `1000000000000000000` — **the EVM reports spendable,
not total.**

The boundary is exact, not a blanket failure:

- 100 QDN (above the 1 QDN spendable, far below the 29.1M total) — rejected,
  `sender balance < tx cost (1000000000000000000 < 100000020000000000000)`.
  The comparison is against spendable.
- 0.5 QDN (within spendable) — **succeeded**, block 276, status 1.
- Entire locked balance, 28,166,666.67 QDN — rejected, `0 < 28166666666666666666666666`.

**Positive control**: a funded `eth_secp256k1` account sent 1 QDN over the EVM
successfully (block 255, status 1, gasUsed 21000). The founder's failures are
the lock, not a broken EVM.

## Environment

- Vesting module: vanilla `cosmos-sdk/x/auth/vesting` (`PeriodicVestingAccount`).
  Not an Evmos-lineage clawback module.
- Cosmos EVM: **v0.5.1**, with `go-ethereum` replaced by
  `cosmos/go-ethereum v1.16.2-cosmos-1`.
- EVM-path ante decorator checking vesting: none by name; enforcement is via
  `SpendableCoin` as traced above.
- `cast balance` reports **spendable**.

## Separate findings

**1. Staking rewards on locked stake are fully liquid.** Expected under vanilla
vesting rules, but worth stating in the token design. Delegating 1,000,000 QDN
of locked principal accrued 115.27 QDN in ~20 blocks; after
`withdraw-rewards`, spendable went from 0.5 to 169.19 QDN, the EVM saw it
immediately, and 100 QDN of it was moved out over the EVM (block 392, status 1).
Locked principal stays locked — `delegated_vesting` tracked the full 1M
correctly — but the yield on it does not.

**2. A fully-locked founder cannot pay EVM gas on a chain with a real base fee.**
This devnet's `base_fee` is `0.000000000000000261` and `min_gas_price` is `0`,
so gas is effectively free and the founder can transact. With any real gas
price the account is frozen out entirely: `sender balance < tx cost
(0 < 21000000000000)`. On a production fee market a founder would be unable to
transact on the EVM side for the whole cliff unless given a small unlocked
float or a feegrant.

**3. The Cosmos bank send is gated by AML before vesting is ever consulted.**
With fees covered by a feegrant, `founder -> victim` failed with qadena code
1159, *"This transfer cannot be AML-scanned; each party must be a wallet with
eKYC data or on the scanned-contract whitelist"* — while `treasury -> victim`
succeeded, and EVM transfers between the same two unKYC'd accounts also
succeeded. The AML gate therefore applies to the Cosmos bank path but not the
EVM transfer path. This does not affect the vesting conclusion (the EVM lock is
enforced independently, as traced above), but the asymmetry looks like it is
worth a separate look.

## Deviations from the brief

- Used the already-running local devnet `qadena_4444-1` rather than initializing
  a fresh `qadena-dev-1`, per instruction to test against the running chain. It
  is a local empty devnet; no mainnet chain-id was used.
- The funding account is `treasury`, not `val` — that is what this devnet has.
- Added a feegrant from treasury so the control test could reach the send
  handler instead of stopping at fee deduction, and added the positive control
  and the exact-boundary tests. Nothing was changed to make a test pass.
