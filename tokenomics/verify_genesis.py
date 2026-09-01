#!/usr/bin/env python3
"""Verify a Qadena genesis.json against allocations.csv and the token design.

    ./verify_genesis.py --genesis ~/qadena/config/genesis.json
    ./verify_genesis.py --csv-only                    # assertions 1-3, no genesis needed

Exits NON-ZERO ON THE FIRST FAILURE, naming the bucket (HARD RULE 6).  A verifier that
reports everything invites triage; one that stops invites a fix.

INTEGER ARITHMETIC ONLY (HARD RULE 3).  Not one float appears below.  `int` is exact at
these magnitudes and `float` is not: 4e27 aqdn has 28 digits and a double carries ~15-16,
so a single float round-trip can silently move a balance by more than a whole QDN.

WHY A VERIFIER EXISTS AT ALL.  genesis.json is a build artifact (HARD RULE 2), so the
question is never "is it edited correctly" but "does what the builder produced still say
what allocations.csv says".  Everything here is derived from the CSV or from the design;
nothing is hardcoded that the CSV could have said instead.
"""

import argparse, csv, json, re, sys
from pathlib import Path

TOTAL_QDN      = 4_000_000_000
AQDN_PER_QDN   = 10**18
TOTAL_AQDN     = TOTAL_QDN * AQDN_PER_QDN          # 4000000000000000000000000000
BASE_DENOM     = "aqdn"
DISPLAY_DENOM  = "qdn"
SYMBOL         = "QDN"
PREFIX         = "qadena"

# The genesis validator: 10,000 QDN self-bond (the min-self-delegation floor) + 100 gas.
VALIDATOR_QDN     = 10_100
VALIDATOR_BOND_QDN = 10_000

# nodeID and nodeType are STATE KEY BYTES and the lookup constants are hardcoded in
# x/qadena (types.IncentivePoolNodeID / NodeType).  Miss this entry and the chain PANICS
# on the first wallet creation -- see assertion 15.
INCENTIVE_POOL_ID = "wallet-incentive-pool"
INCENTIVE_BUCKET  = "01"      # Adoption Programs funds onboarding incentives

CHAIN_ID_RE = re.compile(r"^[a-z]+_[1-9][0-9]*-[1-9][0-9]*$")


class Failed(Exception):
    """Raised with a message naming the bucket or field at fault."""


def fail(msg):
    raise Failed(msg)


# ---------------------------------------------------------------------------- bech32
# Vendored rather than imported: this script must run with a bare interpreter, on a
# machine that may have no network and no pip (the genesis box, deliberately).
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _polymod(values):
    gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk

def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_ok(addr, prefix):
    """True if addr is a valid bech32 string with the given human-readable part."""
    if not addr or any(ord(c) < 33 or ord(c) > 126 for c in addr):
        return False
    if addr.lower() != addr and addr.upper() != addr:
        return False
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return False
    hrp, data = addr[:pos], addr[pos + 1:]
    if hrp != prefix:
        return False
    if any(c not in CHARSET for c in data):
        return False
    vals = [CHARSET.find(c) for c in data]
    return _polymod(_hrp_expand(hrp) + vals) == 1


# ---------------------------------------------------------------------------- CSV
def load_csv(path):
    """Load allocations.csv.  Converts qdn -> aqdn ONCE, here (brief, Phase B)."""
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if not rows:
        fail(f"{path} has no rows")
    for r in rows:
        try:
            r["_qdn"]  = int(r["tokens_qdn"])
            r["_aqdn"] = r["_qdn"] * AQDN_PER_QDN
            r["_pct"]  = int(r["pct"])
        except ValueError as e:
            fail(f"bucket {r.get('bucket_id','?')}: non-integer amount or pct ({e})")
    return rows


def buckets_of(rows):
    """bucket_id -> [rows].  Rows sharing a bucket_id are ONE bucket (Node Ops is two)."""
    b = {}
    for r in rows:
        b.setdefault(r["bucket_id"], []).append(r)
    return b


# ------------------------------------------------------------------- assertions 1-3
def a1_pct_sum(rows, b):
    total = sum(v[0]["_pct"] for v in b.values())
    if total != 100:
        fail(f"assertion 1: distinct-bucket pct sums to {total}, not 100")
    for bid, v in b.items():
        pcts = {r["_pct"] for r in v}
        if len(pcts) != 1:
            fail(f"assertion 1: bucket {bid} rows disagree on pct: {sorted(pcts)}")
    return f"pct sums to 100 across {len(b)} buckets"


def a2_total(rows):
    total = sum(r["_qdn"] for r in rows)
    if total != TOTAL_QDN:
        fail(f"assertion 2: tokens_qdn sums to {total:,}, not {TOTAL_QDN:,} "
             f"(off by {total - TOTAL_QDN:+,})")
    return f"tokens_qdn sums to {TOTAL_QDN:,}"


def a3_per_bucket(b):
    for bid in sorted(b):
        rows = b[bid]
        got = sum(r["_qdn"] for r in rows)
        want = TOTAL_QDN * rows[0]["_pct"] // 100          # integer division, per the brief
        if got != want:
            fail(f"assertion 3: bucket {bid} ({rows[0]['bucket_name']}) sums to {got:,}, "
                 f"expected {want:,} = 4_000_000_000 * {rows[0]['_pct']} // 100 "
                 f"(off by {got - want:+,})")
    return f"every bucket equals pct * {TOTAL_QDN:,} // 100"


# ------------------------------------------------------------------ genesis helpers
def app_state(g):
    return g.get("app_state") or g.get("appState") or fail("genesis has no app_state")


def walk_amounts(node, path="app_state"):
    """Yield (path, denom, amount) for every coin-shaped object anywhere in the tree.

    Coins hide in many shapes -- balances[].coins[], supply[], fee amounts, gentx
    messages -- so assertions 8 and 9 walk rather than enumerate known locations.  A
    check that only looks where it expects is not a check.
    """
    if isinstance(node, dict):
        if "denom" in node and "amount" in node:
            yield path, node["denom"], node["amount"]
        for k, v in node.items():
            yield from walk_amounts(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk_amounts(v, f"{path}[{i}]")


def bank_balances(g):
    return app_state(g).get("bank", {}).get("balances", [])


def aqdn_of(coins):
    for c in coins:
        if c.get("denom") == BASE_DENOM:
            return int(c["amount"])
    return 0


# ------------------------------------------------------------------ assertions 4-9
def a4_supply(g, rows):
    balances = bank_balances(g)
    if not balances:
        fail("assertion 4: genesis bank.balances is empty")
    total = sum(aqdn_of(b.get("coins", [])) for b in balances)
    if total != TOTAL_AQDN:
        fail(f"assertion 4: balances sum to {total} aqdn, expected {TOTAL_AQDN} "
             f"(off by {total - TOTAL_AQDN:+})")
    supply = aqdn_of(app_state(g).get("bank", {}).get("supply", []))
    if supply != TOTAL_AQDN:
        fail(f"assertion 4: bank.supply is {supply} aqdn, expected {TOTAL_AQDN} "
             f"-- supply and balances must agree, or the chain mints or burns at genesis")
    return f"balances and supply both {TOTAL_AQDN} aqdn"


def a5_addresses(g, allow_placeholders):
    seen, dupes = set(), []
    for b in bank_balances(g):
        a = b.get("address", "")
        if a in seen:
            dupes.append(a)
        seen.add(a)
        if not bech32_ok(a, PREFIX):
            if allow_placeholders and a.startswith("<") and a.endswith(">"):
                continue
            fail(f"assertion 5: balance address is not valid bech32 with prefix "
                 f"'{PREFIX}': {a!r}")
    if dupes:
        fail(f"assertion 5: duplicate balance addresses: {sorted(set(dupes))}")
    holders = sum(1 for a in seen if a.startswith("<") and a.endswith(">"))
    if holders:
        return (f"{len(seen)} distinct addresses; {len(seen)-holders} bech32-checked, "
                f"{holders} placeholders SKIPPED (dev build)")
    return f"{len(seen)} distinct, bech32-valid addresses"


# Names x/auth would treat as module accounts.  A module account in the accounts list
# does not merely look wrong: the module derives its own address, so a genesis entry
# under that name creates a SECOND account the module never uses, holding real balance.
MODULE_NAMES = {
    "fee_collector", "mint", "bonded_tokens_pool", "not_bonded_tokens_pool",
    "gov", "distribution", "transfer", "qadena", "feegrant", "authz", "evm", "feemarket",
}

def a6_no_module_accounts(g):
    for acc in app_state(g).get("auth", {}).get("accounts", []):
        name = acc.get("name") or (acc.get("base_account") or {}).get("name")
        if name and name in MODULE_NAMES:
            fail(f"assertion 6: module account '{name}' present in auth.accounts")
        if acc.get("@type", "").endswith("ModuleAccount"):
            fail(f"assertion 6: a ModuleAccount is declared in genesis: {acc.get('name')}")
    return "no module accounts declared"


def a7_denom_metadata(g):
    md = app_state(g).get("bank", {}).get("denom_metadata", [])
    if not md:
        fail("assertion 7: bank.denom_metadata is empty")
    entry = next((m for m in md if m.get("base") == BASE_DENOM), None)
    if entry is None:
        fail(f"assertion 7: no denom_metadata entry with base '{BASE_DENOM}'")
    if entry.get("display") != DISPLAY_DENOM:
        fail(f"assertion 7: display is {entry.get('display')!r}, expected {DISPLAY_DENOM!r}")
    if entry.get("symbol") != SYMBOL:
        fail(f"assertion 7: symbol is {entry.get('symbol')!r}, expected {SYMBOL!r} (uppercase)")
    units = {u.get("denom"): u for u in entry.get("denom_units", [])}
    for denom, exp in ((BASE_DENOM, 0), (DISPLAY_DENOM, 18)):
        if denom not in units:
            fail(f"assertion 7: denom_units has no entry for {denom!r}")
        # EXPONENT MUST BE PRESENT, not merely correct-by-omission.  Cosmos omits
        # exponent 0 when marshalling, and a reader that defaults it cannot tell an
        # explicit 0 from a missing field.
        if "exponent" not in units[denom]:
            fail(f"assertion 7: denom_units[{denom}] has no explicit exponent")
        if int(units[denom]["exponent"]) != exp:
            fail(f"assertion 7: {denom} exponent is {units[denom]['exponent']}, expected {exp}")
    return "base aqdn, display qdn, symbol QDN, exponents 0 and 18 explicit"


def a8_no_display_denom(g):
    for path, denom, _ in walk_amounts(app_state(g)):
        if denom == DISPLAY_DENOM:
            fail(f"assertion 8: an on-chain amount uses the DISPLAY denom '{DISPLAY_DENOM}' "
                 f"at {path} -- every on-chain amount must be in '{BASE_DENOM}'")
    return f"no on-chain amount uses '{DISPLAY_DENOM}'"


def a9_amounts_are_strings(g):
    for path, _, amount in walk_amounts(app_state(g)):
        if not isinstance(amount, str):
            fail(f"assertion 9: amount at {path} is {type(amount).__name__} "
                 f"({amount!r}), must be a JSON string -- a JSON number cannot hold "
                 f"{TOTAL_AQDN} without loss")
    return "every amount is a JSON string"


# ----------------------------------------------------------------- assertions 10-16
ONE_PERCENT = "0.010000000000000000"

def a10_mint(g):
    p = app_state(g).get("mint", {}).get("params", {})
    if not p:
        fail("assertion 10: mint.params is missing")
    if p.get("mint_denom") != BASE_DENOM:
        fail(f"assertion 10: mint_denom is {p.get('mint_denom')!r}, expected {BASE_DENOM!r}")
    lo, hi = p.get("inflation_min"), p.get("inflation_max")
    if lo != hi:
        fail(f"assertion 10: inflation_min ({lo}) != inflation_max ({hi}) -- the design is a "
             f"FIXED 1% rate, and a band would let it drift")
    # Compare as integers scaled by 1e18: string equality would reject an equivalent
    # "0.01", and float equality is not allowed here at all.
    try:
        scaled = int(str(lo).replace(".", "").lstrip("0") or "0")
        expect = int(ONE_PERCENT.replace(".", "").lstrip("0"))
    except ValueError:
        fail(f"assertion 10: inflation_min {lo!r} is not a decimal string")
    if scaled != expect:
        fail(f"assertion 10: inflation is {lo}, expected {ONE_PERCENT} (1.00% fixed)")
    if str(p.get("inflation_rate_change", "")).strip("0.") != "":
        fail(f"assertion 10: inflation_rate_change is {p.get('inflation_rate_change')!r}, "
             f"expected 0 -- with min == max there is nothing to change between")
    bpy = p.get("blocks_per_year")
    if bpy in (None, "", "6311520"):      # 6311520 is the Cosmos default
        fail(f"assertion 10: blocks_per_year is {bpy!r} -- it must be computed from a "
             f"MEASURED block time, not left at the SDK default")
    return f"inflation fixed at {lo}, blocks_per_year {bpy}"


def a11_no_second_emission(g):
    """x/mint must be the only thing that can create QDN at genesis.

    THIS CHECKS EMISSION, NOT MODULE PRESENCE.  An earlier version failed on the mere
    existence of `epochs`, which on this chain is a plain timer (day/hour identifiers,
    shipped by cosmos/evm) that emits nothing -- it would have blocked every real build.
    Presence of a module is not evidence; a declared reward stream is.

    Read as a smoke test either way.  It can only see what genesis DECLARES.  A
    BeginBlocker that pays the fee collector lives in CODE, and no genesis check will
    ever find it -- that half stays a code review.
    """
    st = app_state(g)

    # Only x/mint may carry inflation parameters.
    for mod, body in st.items():
        if mod == "mint" or not isinstance(body, dict):
            continue
        params = body.get("params")
        if isinstance(params, dict):
            for key in params:
                if "inflation" in key.lower() or "mint" in key.lower():
                    fail(f"assertion 11: module '{mod}' declares an emission parameter "
                         f"'{key}' -- x/mint must be the only source of new QDN")

    # The community pool must start empty: a pre-funded fee_pool is supply that never
    # appears in bank.balances and so slips past assertion 4.
    pool = st.get("distribution", {}).get("fee_pool", {})
    for path, denom, amount in walk_amounts(pool, "distribution.fee_pool"):
        if denom == BASE_DENOM and int(str(amount).split(".")[0] or 0) != 0:
            fail(f"assertion 11: distribution.fee_pool starts non-empty at {path} "
                 f"({amount}) -- genesis must not pre-fund the community pool")

    # Reward streams that some chains bolt on. Flagged only if they declare content.
    for mod in ("incentives", "streamswap", "airdrop", "claim"):
        body = st.get(mod)
        if isinstance(body, dict) and any(body.values()):
            fail(f"assertion 11: module '{mod}' is present AND non-empty -- it is a "
                 f"second emission path unless proven otherwise")
    return "x/mint is the only declared emission path; fee_pool empty"


def a12_validator_row(g, rows):
    # THE VALIDATOR IS THE SELF-BONDING ROW, not merely a `base` one.  pioneer1 is also
    # genesis_type `base` -- it is a bootstrap identity funded from bucket 12, and it does
    # not stake -- so `stakes` is what distinguishes them.
    base_rows = [r for r in rows if r["stakes"].strip().lower() == "self-bond"]
    if len(base_rows) != 1:
        fail(f"assertion 12: expected exactly one row with stakes=self-bond (the genesis "
             f"validator), found {len(base_rows)}")
    v = base_rows[0]
    if v["_qdn"] != VALIDATOR_QDN:
        fail(f"assertion 12: validator row is {v['_qdn']:,} QDN, expected {VALIDATOR_QDN:,} "
             f"({VALIDATOR_BOND_QDN:,} self-bond + 100 gas)")
    gentxs = app_state(g).get("genutil", {}).get("gen_txs", [])
    if len(gentxs) != 1:
        fail(f"assertion 12: expected exactly one gentx, found {len(gentxs)}")
    # The self-bond inside the gentx must equal the min-self-delegation floor, or the
    # genesis validator and every later joiner are held to different numbers.
    bond = None
    for path, denom, amount in walk_amounts(gentxs[0], "gentx"):
        if denom == BASE_DENOM and "value" in path:
            bond = int(amount)
            break
    if bond is None:
        fail("assertion 12: could not find the self-bond amount inside the gentx")
    want = VALIDATOR_BOND_QDN * AQDN_PER_QDN
    if bond != want:
        fail(f"assertion 12: gentx self-bond is {bond} aqdn, expected {want} "
             f"({VALIDATOR_BOND_QDN:,} QDN = the min-self-delegation floor)")
    return f"one validator row of {VALIDATOR_QDN:,} QDN, one gentx bonding {VALIDATOR_BOND_QDN:,}"


def a13_no_placeholders(rows, allow_placeholders):
    bad = [r for r in rows
           if r["genesis_address"].startswith("<") and r["genesis_address"].endswith(">")]
    if bad and not allow_placeholders:
        names = ", ".join(f"{r['bucket_id']} ({r['bucket_name']})" for r in bad)
        fail(f"assertion 13: {len(bad)} row(s) still hold a PLACEHOLDER address: {names}. "
             f"Pass --allow-placeholders for a dev build; a mainnet build must not.")
    if bad:
        return f"{len(bad)} placeholder addresses ALLOWED (dev build)"
    return "every address is real"


def a14_whitelist(g, rows, allow_placeholders):
    """Every bucket address and the validator must be on the scanned-contract whitelist.

    Without this the chain launches with buckets that cannot move a single token: an
    account that is not a qadena wallet and not whitelisted is refused with code 1159,
    and the only remedy is one governance proposal per bucket.
    """
    wl = app_state(g).get("qadena", {}).get("scannedContractWhitelistList", [])
    listed = {e.get("address"): e for e in wl}
    for r in rows:
        addr = r["genesis_address"]
        if addr.startswith("<") and allow_placeholders:
            continue
        if addr not in listed:
            fail(f"assertion 14: bucket {r['bucket_id']} ({r['bucket_name']}) address {addr} "
                 f"is NOT in scannedContractWhitelistList -- it could not move a token")
        code_id = listed[addr].get("codeID", listed[addr].get("code_id"))
        if int(code_id or 0) != 0:
            fail(f"assertion 14: bucket {r['bucket_id']} whitelist entry has codeID "
                 f"{code_id}, expected 0 -- these are plain accounts, not contracts")
    return f"all {len(rows)} genesis addresses whitelisted with codeID 0"


def a15_incentive_pool(g, rows, allow_placeholders):
    """The incentive-pool identity must exist and point at the Adoption bucket.

    x/qadena looks it up by HARDCODED constants and PANICS if it is absent -- so a
    genesis without this entry produces a chain that dies on the first wallet creation.
    """
    ipl = app_state(g).get("qadena", {}).get("intervalPublicKeyIDList", [])
    entry = next((e for e in ipl
                  if e.get("nodeID") == INCENTIVE_POOL_ID
                  and e.get("nodeType") == INCENTIVE_POOL_ID), None)
    if entry is None:
        got = [(e.get("nodeID"), e.get("nodeType")) for e in ipl]
        fail(f"assertion 15: no intervalPublicKeyIDList entry with nodeID == nodeType == "
             f"'{INCENTIVE_POOL_ID}'. Wallet creation will PANIC. Found: {got}")
    pubkid = entry.get("pubKID", "")
    adoption = next((r for r in rows if r["bucket_name"] == "Wallet Incentive Pool"), None)
    if adoption is None:
        fail(f"assertion 15: no 'Wallet Incentive Pool' row in the CSV to fund the pool")
    if pubkid.startswith("<") or adoption["genesis_address"].startswith("<"):
        if not allow_placeholders:
            fail(f"assertion 15: incentive-pool pubKID or bucket {INCENTIVE_BUCKET} address "
                 f"is still a placeholder")
        return "incentive-pool present (placeholder address, dev build)"
    if not bech32_ok(pubkid, PREFIX):
        fail(f"assertion 15: incentive-pool pubKID {pubkid!r} is not a valid {PREFIX} "
             f"address -- the PubKID IS the address the chain debits")
    if pubkid != adoption["genesis_address"]:
        fail(f"assertion 15: incentive-pool points at {pubkid}, but bucket "
             f"{INCENTIVE_BUCKET} ({adoption['bucket_name']}) is {adoption['genesis_address']}")
    return f"incentive-pool -> bucket {INCENTIVE_BUCKET} ({adoption['bucket_name']})"


def a16_chain_id(g, expect_evm_id=None):
    """chain_id must be <name>_<eip155>-<epoch>.

    The EVM chain ID is PARSED out of this string, and a mismatch FAILS SILENTLY --
    cmd/qadenad/cmd/commands.go returns without setting EVMChainID and the EVM runs on a
    fallback.  Nothing logs it.
    """
    cid = g.get("chain_id") or g.get("chainId")
    if not cid:
        fail("assertion 16: genesis has no chain_id")
    if not CHAIN_ID_RE.match(cid):
        fail(f"assertion 16: chain_id {cid!r} does not match <name>_<eip155>-<epoch>. "
             f"The EVM chain ID is parsed from it and a mismatch fails SILENTLY.")
    eip155 = int(cid.split("_")[1].split("-")[0])
    if expect_evm_id is not None and eip155 != expect_evm_id:
        fail(f"assertion 16: chain_id carries EIP-155 id {eip155}, expected {expect_evm_id}")
    return f"chain_id {cid} (EIP-155 {eip155})"


# ---------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).parent
    ap.add_argument("--genesis", type=Path, help="path to genesis.json")
    ap.add_argument("--csv", type=Path, default=here / "allocations.csv")
    ap.add_argument("--csv-only", action="store_true",
                    help="run assertions 1-3 only; no genesis needed")
    ap.add_argument("--allow-placeholders", action="store_true",
                    help="permit <NN_MSIG_ADDR> addresses.  DEV BUILDS ONLY -- a mainnet "
                         "build must fail on these (assertion 13)")
    ap.add_argument("--pre-gentx", action="store_true",
                    help="the genesis has not been through `collect-gentxs` yet, so skip "
                         "assertion 12.  This is the artifact stage of the documented flow: "
                         "publish accounts+balances+params, validators gentx against it, "
                         "collect, THEN verify in full")
    ap.add_argument("--expect-evm-id", type=int,
                    help="require this EIP-155 id in chain_id (mainnet 482, "
                         "testnet 4824, devnet 4828)")
    args = ap.parse_args()

    if not args.csv_only and not args.genesis:
        ap.error("--genesis is required unless --csv-only is given")

    rows = load_csv(args.csv)
    b = buckets_of(rows)

    checks = [
        ("1  pct sum",            lambda: a1_pct_sum(rows, b)),
        ("2  total tokens_qdn",   lambda: a2_total(rows)),
        ("3  per-bucket sums",    lambda: a3_per_bucket(b)),
    ]

    g = None
    if not args.csv_only:
        try:
            g = json.loads(args.genesis.read_text())
        except Exception as e:
            print(f"FAIL  could not read {args.genesis}: {e}", file=sys.stderr)
            return 1
        checks += [
            ("4  supply == balances", lambda: a4_supply(g, rows)),
            ("5  addresses",          lambda: a5_addresses(g, args.allow_placeholders)),
            ("6  no module accounts", lambda: a6_no_module_accounts(g)),
            ("7  denom metadata",     lambda: a7_denom_metadata(g)),
            ("8  no display denom",   lambda: a8_no_display_denom(g)),
            ("9  amounts are strings",lambda: a9_amounts_are_strings(g)),
            ("10 mint params",        lambda: a10_mint(g)),
            ("11 no 2nd emission",    lambda: a11_no_second_emission(g)),
            ("12 validator + gentx",  lambda: (a12_validator_row(g, rows)
                                              if not args.pre_gentx else
                                              "SKIPPED (--pre-gentx): no gentx collected yet")),
            ("13 no placeholders",    lambda: a13_no_placeholders(rows, args.allow_placeholders)),
            ("14 AML whitelist",      lambda: a14_whitelist(g, rows, args.allow_placeholders)),
            ("15 incentive-pool",     lambda: a15_incentive_pool(g, rows, args.allow_placeholders)),
            ("16 chain_id form",      lambda: a16_chain_id(g, args.expect_evm_id)),
        ]
    else:
        checks.append(("13 no placeholders",
                       lambda: a13_no_placeholders(rows, args.allow_placeholders)))

    if args.allow_placeholders:
        print("!! --allow-placeholders: THIS IS A DEV BUILD, not a mainnet one")
    if args.pre_gentx:
        print("!! --pre-gentx: assertion 12 SKIPPED; re-run after collect-gentxs")
    if args.allow_placeholders or args.pre_gentx:
        print()

    for name, fn in checks:
        try:
            detail = fn()
        except Failed as e:
            # EXIT ON THE FIRST FAILURE (HARD RULE 6).
            print(f"FAIL  {name}", file=sys.stderr)
            print(f"      {e}", file=sys.stderr)
            return 1
        print(f"ok    {name:<22} {detail}")

    scope = "CSV only" if args.csv_only else f"CSV + {args.genesis}"
    print(f"\nPASS  {len(checks)} assertions ({scope})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
