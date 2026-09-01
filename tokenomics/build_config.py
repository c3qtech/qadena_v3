#!/usr/bin/env python3
"""Render an ignite-runnable config.yml from launch-config.yml + allocations.csv.

    ./build_config.py --out /tmp/config.yml            # dev: placeholders stay
    ./build_config.py --addresses addrs.csv --strict   # real addresses, mainnet gate

THE PIPELINE THIS SITS IN

    config/launch-config.yml   token design: accounts, x/qadena state, every module param
    tokenomics/allocations.csv AMOUNTS (human-owned, authoritative)
             |
             v   this script
        config.yml  --ignite chain init-->  genesis.json  --verify_genesis.py-->  ok
             |                                   (buildscripts/init.sh does the init)

WHY RENDER A CONFIG RATHER THAN A GENESIS.  An earlier version of build_genesis.py
patched a bare `qadenad init` skeleton, and the result was arithmetically perfect and
UNBOOTABLE: `qadenad init` writes an EMPTY x/qadena section -- no enclaveIdentityList, no
publicKeyList -- so the chain trusted no SGX measurement and pioneer1 had no keys.  All of
that already exists, correct, in launch-config.yml.  Rendering a config and letting ignite
translate it keeps ONE definition of the chain instead of two.

HOW MULTISIGS ARE HANDLED -- the short answer is "as addresses, and nothing else"
--------------------------------------------------------------------------------
A bucket is a native n-of-m multisig, but genesis needs only its ADDRESS:

  * The address is a pure function of the member PUBLIC keys and the threshold, and is
    derivable entirely offline -- `qadenad keys add <n> --multisig a,b,c
    --multisig-threshold 2` touches no chain and needs no private key.
  * Genesis writes a plain BaseAccount there with `pub_key: null`.  The multisig's
    LegacyAminoPubKey is presented at FIRST SIGNATURE, not in genesis -- which is why a
    bucket can be funded at genesis by an address alone.
  * So HARD RULE 5 holds: whoever controls the keys derives the address in real custody
    and hands over a STRING.  Nothing here generates or holds a key.

Two accounts are NOT like that and do need a real key on the building machine:

  * pioneer1  -- buildscripts/setPubKAndPubKID.sh resolves `pioneer1PubKID` from the
                 KEYRING, so the key must exist locally at init time.
  * genval1   -- signs the gentx.

That asymmetry is the practical form of the pioneer1/treasury open question: the ten
buckets can be cold multisigs held anywhere, and the two bootstrap identities cannot.
"""

import argparse, csv, json, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TOTAL_QDN = 4_000_000_000
SLUG = {"01": "adoption", "01w": "wallet-incentive-pool", "02": "ltr", "03": "foundation", "04": "grants",
        "05": "personnel", "06": "backers", "07": "founders", "09": "contingency",
        "10": "pubsec", "12": "nodeops"}
GENVAL = "genval1"
# Rows whose account name is not derivable from bucket_id alone.  Keyed on the
# genesis_address placeholder because it is the one field unique to every row: buckets 01
# and 12 each hold several rows, and TWO of them are genesis_type `base` (pioneer1 and
# genval1), so neither bucket_id nor genesis_type identifies a row on its own.
NAME_OF = {"<01_WIP_ADDR>": "wallet-incentive-pool",
           "<PIONEER1_ADDR>": "pioneer1",
           "<GENVAL_1_ADDR>": GENVAL}
RUNTIME_KEYS = ["validation", "client", "build", "validators"]


# WHICH ACCOUNT DOES A CSV ROW BELONG TO?
#
# Not derivable from bucket_id alone: buckets 01 and 12 hold several rows each, and TWO of
# them are genesis_type `base` (pioneer1 and genval1).
#
# An earlier version keyed on the genesis_address PLACEHOLDER, which worked only while the
# placeholders existed -- the moment real addresses were pasted in, every multi-row bucket
# silently mis-mapped and the verifier reported the wrong account's amount as wrong.  Key on
# fields that do not change when an address is filled in.
def account_of(row, slug, genval="genval1"):
    if row["bucket_name"].strip() == "Wallet Incentive Pool":
        return "wallet-incentive-pool"
    if row["genesis_type"].strip() == "base":
        # the VALIDATOR is the self-bonding one; pioneer1 is the other bootstrap identity
        return genval if row["stakes"].strip().lower() == "self-bond" else "pioneer1"
    return slug.get(row["bucket_id"])


def yload(path):
    out = subprocess.run(["yq", "-o=json", ".", str(path)], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"build_config: yq failed on {path}: {out.stderr.strip()}")
    return json.loads(out.stdout)


def ydump(obj, path):
    out = subprocess.run(["yq", "-P", "-o=yaml", "."], input=json.dumps(obj),
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"build_config: yq failed writing {path}: {out.stderr.strip()}")
    Path(path).write_text(out.stdout)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).parent
    ap.add_argument("--launch-config", type=Path,
                    default=here.parent / "config" / "launch-config.yml")

    ap.add_argument("--csv", type=Path, default=here / "allocations.csv")
    ap.add_argument("--addresses", type=Path,
                    help="CSV of name,address to substitute for TODO_ADDR_* and for the "
                         "CSV's <PLACEHOLDER> genesis_address values")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--strict", action="store_true",
                    help="refuse to write while any placeholder remains (mainnet gate)")
    args = ap.parse_args()

    lc = yload(args.launch_config)
    rows = list(csv.DictReader(open(args.csv, encoding="utf-8")))

    supplied = {}
    if args.addresses:
        for r in csv.DictReader(open(args.addresses, encoding="utf-8")):
            supplied[r["name"].strip()] = r["address"].strip()

    # RUNTIME COMES FROM launch-config.yml, AND THERE IS NO FALLBACK.
    #
    # An earlier version took these from config/config.yml "so as not to invent values".
    # That was wrong: config.yml is the TEST chain, and its values are wrong for mainnet in
    # ways that do not announce themselves -- validator pioneer1 instead of genval1, bonded
    # 100000qdn instead of 10000, and timeout_commit 1.5s against a blocks_per_year that
    # assumes 3s.  That last pairing would over-mint for the life of the chain.
    #
    # So a missing stanza is a LOUD failure, never a quiet substitution.
    cfg = {"version": lc.get("version", 1)}
    for k in RUNTIME_KEYS:
        if k not in lc:
            sys.exit(f"build_config: {args.launch_config} has no '{k}' stanza.\n"
                     f"  The node runtime for this chain must be declared THERE, not borrowed\n"
                     f"  from config/config.yml -- that is the devnet, and its validator name,\n"
                     f"  bond and timeout_commit are all wrong for a launch.")
        cfg[k] = lc[k]

    # accounts: names and structure from launch-config, AMOUNTS from the CSV
    by_name = {a["name"]: dict(a) for a in lc.get("accounts", [])}
    for row in rows:
        # bucket 01 and 12 each hold MORE THAN ONE row, so map by NAME, not by bucket_id.
        name = account_of(row, SLUG, GENVAL)
        if name in by_name:
            by_name[name]["coins"] = [f"{int(row['tokens_qdn'])}qdn"]
            if name in supplied:
                by_name[name]["address"] = supplied[name]
    for n, a in by_name.items():
        if n in supplied:
            a["address"] = supplied[n]
    cfg["accounts"] = list(by_name.values())

    genesis = json.loads(json.dumps(lc.get("genesis", {})))
    genesis["chain_id"] = lc.get("chain_id", genesis.get("chain_id"))

    # THE WHITELIST THE FILE WAS MISSING.  Every bucket must be listed or it cannot move
    # a token (code 1159), and the only remedy after launch is one proposal per bucket.
    q = genesis.setdefault("app_state", {}).setdefault("qadena", {})
    wl = [e for e in (q.get("scannedContractWhitelistList") or [])]
    have = {e.get("address") for e in wl}
    added = 0
    for row in rows:
        # bucket 01 and 12 each hold MORE THAN ONE row, so map by NAME, not by bucket_id.
        name = account_of(row, SLUG, GENVAL)
        addr = by_name.get(name, {}).get("address")
        if addr and addr not in have:
            wl.append({"address": addr, "codeID": 0,
                       "reason": f"{row['bucket_name']} genesis custody"})
            have.add(addr)
            added += 1
    q["scannedContractWhitelistList"] = wl

    # incentive-pool must follow the Adoption address wherever it moved to
    pool_addr = by_name.get("wallet-incentive-pool", {}).get("address")
    ipl = [e for e in (q.get("intervalPublicKeyIDList") or [])]
    for e in ipl:
        if e.get("nodeID") == "wallet-incentive-pool":
            e["pubKID"] = pool_addr
    q["intervalPublicKeyIDList"] = ipl

    cfg["genesis"] = genesis

    text = json.dumps(cfg)
    leftover = sorted({t for t in text.split('"') if t.startswith("TODO_")})
    placeholders = sorted({r["genesis_address"] for r in rows
                           if r["genesis_address"].startswith("<")})
    if args.strict and (leftover or placeholders):
        print("REFUSING to write: unresolved placeholders remain", file=sys.stderr)
        for t in leftover:
            print(f"   {t}", file=sys.stderr)
        for t in placeholders:
            print(f"   {t} (allocations.csv genesis_address)", file=sys.stderr)
        return 1

    ydump(cfg, args.out)
    total = sum(int(r["tokens_qdn"]) for r in rows)
    print(f"wrote {args.out}")
    print(f"  accounts       {len(cfg['accounts'])} ({total:,} qdn across {len(rows)} CSV rows)")
    print(f"  runtime from   {args.launch_config} ({', '.join(RUNTIME_KEYS)})")
    print(f"  whitelist      +{added} bucket entries added ({len(wl)} total)")
    print(f"  chain_id       {genesis.get('chain_id')}")
    if leftover or placeholders:
        print(f"  UNRESOLVED     {len(leftover)+len(placeholders)} placeholder(s) -- dev only")
    # buildscripts/init.sh:148 does `cp config/config.yml config.yml` UNCONDITIONALLY, so a
    # rendered file left at the repo root is silently discarded.  config/config.yml is the only
    # input init.sh reads.
    target = ROOT / "config" / "config.yml"
    if args.out.resolve() != target.resolve():
        print(f"\n!! {args.out} is NOT config/config.yml.")
        print(f"   buildscripts/init.sh copies config/config.yml -> config.yml unconditionally")
        print(f"   (init.sh:148), so anything left elsewhere -- including at the repo root -- is")
        print(f"   DISCARDED.  To actually build this chain:")
        print(f"       cp {args.out} config/config.yml     # replaces the DEVNET config")
        print(f"       buildscripts/init.sh")
        print(f"   Or render straight there: --out config/config.yml")
        print(f"   Either way config/config.yml is tracked in git -- committing or stashing it")
        print(f"   first is what makes the devnet recoverable.")
    else:
        print(f"\nNEXT: buildscripts/init.sh          (ignite builds genesis.json from this)")
    print(f"      then: tokenomics/verify_genesis.py --genesis $QADENAHOME/config/genesis.json --pre-gentx")
    return 0


if __name__ == "__main__":
    sys.exit(main())
