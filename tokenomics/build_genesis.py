#!/usr/bin/env python3
"""Build a Qadena genesis.json from allocations.csv.

    qadenad init qadena --chain-id qadena_4828-1 --home /tmp/g      # skeleton
    ./build_genesis.py --base /tmp/g/config/genesis.json \
                       --chain-id qadena_4828-1 --blocks-per-year 21024000 \
                       --out genesis.json --allow-placeholders --verify

IT PATCHES A REAL SKELETON, IT DOES NOT FABRICATE ONE.  A Cosmos genesis carries
consensus params and a dozen module sections -- evm, feemarket, ibc, wasm, qadena,
pricefeed -- that only the binary knows how to produce, and whose shape changes with the
SDK.  Generating those by hand would be a second, silently-drifting definition of the
chain.  So `qadenad init` writes the skeleton and this script sets ONLY what the token
design owns:

    auth.accounts                          one BaseAccount per CSV row
    bank.balances / bank.supply            from tokens_qdn, converted ONCE
    bank.denom_metadata                    aqdn/qdn, exponents explicit
    mint.params                            1% fixed
    qadena.scannedContractWhitelistList    every bucket, codeID 0
    qadena.intervalPublicKeyIDList         the incentive-pool entry

Everything else in the base is passed through untouched.

DETERMINISTIC OUTPUT.  Keys are sorted and separators fixed, so the same inputs give a
byte-identical file and therefore the same SHA256.  The definition of done requires a
second person to reproduce that hash from this repo; a builder whose output depends on
dict ordering cannot satisfy it.

INTEGER ARITHMETIC ONLY (HARD RULE 3), and every amount is written as a STRING
(HARD RULE 4).  `genesis.json` is a build artifact -- never hand-edit it (HARD RULE 2);
re-run this instead.
"""

import argparse, csv, hashlib, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import verify_genesis as V


def load_rows(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    for r in rows:
        r["_qdn"] = int(r["tokens_qdn"])
        r["_aqdn"] = r["_qdn"] * V.AQDN_PER_QDN
    return rows


def base_account(addr, number):
    return {
        "@type": "/cosmos.auth.v1beta1.BaseAccount",
        "address": addr,
        "pub_key": None,
        "account_number": str(number),
        "sequence": "0",
    }


def build(base, rows, chain_id, blocks_per_year):
    g = json.loads(json.dumps(base))          # deep copy; never mutate the caller's base
    g["chain_id"] = chain_id
    st = g.setdefault("app_state", {})

    # --- auth.accounts -------------------------------------------------------
    # NO VESTING ACCOUNTS AND NO CONTRACTS AT GENESIS.  Every bucket lands as a plain
    # BaseAccount, fully liquid; every lock is applied after launch.  A vesting account
    # here would also be unrecoverable if wrong: MsgCreatePeriodicVestingAccount refuses
    # an address that already exists.
    auth = st.setdefault("auth", {})
    auth["accounts"] = [base_account(r["genesis_address"], i)
                        for i, r in enumerate(rows)]

    # --- bank ----------------------------------------------------------------
    bank = st.setdefault("bank", {})
    bank["balances"] = [
        {"address": r["genesis_address"],
         "coins": [{"denom": V.BASE_DENOM, "amount": str(r["_aqdn"])}]}
        for r in rows
    ]
    total = sum(r["_aqdn"] for r in rows)
    bank["supply"] = [{"denom": V.BASE_DENOM, "amount": str(total)}]
    bank["denom_metadata"] = [{
        "description": "The native token of the Qadena network",
        "base": V.BASE_DENOM,
        "display": V.DISPLAY_DENOM,
        "name": "Qadena Token",
        "symbol": V.SYMBOL,
        # Exponents are written EXPLICITLY, including the 0.  Cosmos omits a zero
        # exponent when marshalling, and a reader cannot then tell an explicit 0 from a
        # missing field -- assertion 7 requires it to be present.
        "denom_units": [
            {"denom": V.BASE_DENOM, "exponent": 0, "aliases": []},
            {"denom": V.DISPLAY_DENOM, "exponent": 18, "aliases": []},
        ],
    }]

    # --- mint ----------------------------------------------------------------
    mint = st.setdefault("mint", {}).setdefault("params", {})
    mint["mint_denom"] = V.BASE_DENOM
    mint["inflation_min"] = V.ONE_PERCENT
    mint["inflation_max"] = V.ONE_PERCENT
    mint["inflation_rate_change"] = "0"
    mint["blocks_per_year"] = str(blocks_per_year)

    # --- qadena --------------------------------------------------------------
    q = st.setdefault("qadena", {})

    # WHITELIST EVERY BUCKET AT GENESIS.  An account that is not a qadena wallet and not
    # listed here is refused with code 1159 and cannot move a token; the only remedy
    # after launch is one governance proposal per bucket.  codeID 0 because these are
    # plain accounts, not contracts -- treasury is seeded the same way.
    q["scannedContractWhitelistList"] = [
        {"address": r["genesis_address"], "codeID": 0,
         "reason": f"{r['bucket_name']} genesis custody"}
        for r in rows
    ]

    # THE INCENTIVE POOL.  x/qadena finds this by HARDCODED constants
    # (types.IncentivePoolNodeID / NodeType) and PANICS if it is absent, so a genesis
    # without it produces a chain that dies on its first wallet creation.  The PubKID IS
    # the address the chain debits for create_wallet incentives; it points at the
    # Adoption bucket, whose stated purpose is exactly that.
    adoption = next((r for r in rows if r["bucket_id"] == V.INCENTIVE_BUCKET), None)
    if adoption is None:
        sys.exit(f"build_genesis: no bucket {V.INCENTIVE_BUCKET} in the CSV to fund the "
                 f"incentive pool")
    existing = [e for e in q.get("intervalPublicKeyIDList", [])
                if e.get("nodeID") != V.INCENTIVE_POOL_ID]
    q["intervalPublicKeyIDList"] = existing + [{
        "pubKID": adoption["genesis_address"],
        "nodeType": V.INCENTIVE_POOL_ID,
        "nodeID": V.INCENTIVE_POOL_ID,
    }]
    return g


def dump(g, path):
    """Write deterministically and return the SHA256 of what was written."""
    text = json.dumps(g, sort_keys=True, indent=1, separators=(",", ": ")) + "\n"
    Path(path).write_text(text)
    return hashlib.sha256(text.encode()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).parent
    ap.add_argument("--base", type=Path, required=True,
                    help="genesis.json skeleton from `qadenad init` -- everything this "
                         "script does not own is passed through from it")
    ap.add_argument("--csv", type=Path, default=here / "allocations.csv")
    ap.add_argument("--out", type=Path, default=here / "genesis.json")
    ap.add_argument("--chain-id", required=True,
                    help="must be <name>_<eip155>-<epoch>; the EVM chain ID is parsed "
                         "from it and a mismatch fails SILENTLY")
    # ONE OF THESE, NOT BOTH.  --block-time is preferred because it makes the derivation
    # explicit and is what the brief actually asks for: measure, then divide.
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--block-time", type=float, metavar="SECONDS",
                   help="MEASURED seconds per block. blocks_per_year = 31536000 / this. "
                        "Measure it, do not read it off timeout_commit: timeout_commit is a "
                        "floor, and a chain that beats it mints MORE than intended")
    g.add_argument("--blocks-per-year", type=int,
                   help="the computed value directly, if you already have it")
    ap.add_argument("--allow-placeholders", action="store_true",
                    help="permit <NN_MSIG_ADDR>.  DEV BUILDS ONLY")
    ap.add_argument("--verify", action="store_true",
                    help="run verify_genesis against the result before exiting")
    args = ap.parse_args()

    if not V.CHAIN_ID_RE.match(args.chain_id):
        sys.exit(f"build_genesis: --chain-id {args.chain_id!r} is not <name>_<eip155>-<epoch>")

    # 31,536,000 = 365 days.  Integer division: the remainder is under one block a year.
    if args.block_time:
        if args.block_time <= 0:
            sys.exit("build_genesis: --block-time must be positive")
        bpy = int(31_536_000 / args.block_time)
    else:
        bpy = args.blocks_per_year

    rows = load_rows(args.csv)
    base = json.loads(args.base.read_text())
    g = build(base, rows, args.chain_id, bpy)
    digest = dump(g, args.out)

    print(f"wrote  {args.out}")
    print(f"        {len(rows)} accounts, {sum(r['_qdn'] for r in rows):,} QDN")
    implied = 31_536_000 / bpy
    src = f"measured {args.block_time}s/block" if args.block_time else "given directly"
    print(f"        chain-id {args.chain_id}")
    print(f"        blocks_per_year {bpy:,} ({src}; implies {implied:.3f}s per block)")
    # SANITY, NOT A GATE.  Under-stating the block rate makes x/mint pay more per block
    # than intended -- the error is silent and compounds for the life of the chain.
    if abs(implied - 1.5) < 0.001 or abs(implied - 3.0) < 0.001:
        print(f"        NOTE: {implied:.1f}s is a timeout_commit TARGET, not a measurement. "
              f"A chain that runs faster will over-mint.")
    print(f"SHA256 {digest}")

    if args.verify:
        print()
        # Its own output is by definition PRE-GENTX: this script writes the artifact that
        # validators then gentx against.  Assertion 12 belongs to the post-collect check.
        argv = ["--genesis", str(args.out), "--csv", str(args.csv), "--pre-gentx",
                "--expect-evm-id", args.chain_id.split("_")[1].split("-")[0]]
        if args.allow_placeholders:
            argv.append("--allow-placeholders")
        sys.argv = ["verify_genesis.py"] + argv
        rc = V.main()
        if rc != 0:
            sys.exit(rc)
    else:
        print("\nNot verified.  Run:")
        print(f"  ./verify_genesis.py --genesis {args.out} --pre-gentx"
              f"{' --allow-placeholders' if args.allow_placeholders else ''}")
    print("\nNEXT: gentx, then collect-gentxs, then re-verify WITHOUT --pre-gentx.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
