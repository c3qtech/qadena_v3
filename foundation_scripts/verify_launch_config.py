#!/usr/bin/env python3
"""Pre-flight for config/launch-config.yml -- the file the mainnet genesis is built FROM.

    ./verify_launch_config.py                     # what is still unset, and what disagrees
    ./verify_launch_config.py --strict            # exit 1 unless it is launch-ready

WHY THIS EXISTS SEPARATELY FROM verify_genesis.py
-------------------------------------------------
verify_genesis.py checks the ARTIFACT, after it is built.  By then a wrong value has
already been baked in and hashed.  This checks the INPUT, where a wrong value is still
one edit away from being right -- and where most of the decisions actually live.

launch-config.yml is where the accounts are pre-loaded: the ten buckets and the genesis
validator, their amounts, the AML whitelist, the incentive-pool identity and every module
param.  allocations.csv is the human-owned source for the AMOUNTS; this file is where they
have to be transcribed to, and transcription is exactly the step that drifts.

It reads YAML through `yq -o=json` rather than PyYAML, because this box has no PyYAML and
the genesis machine may have neither.
"""

import argparse, csv, json, re, subprocess, sys
from pathlib import Path

AQDN_SUFFIX = "qdn"
TOTAL_QDN = 4_000_000_000
INCENTIVE_POOL_ID = "wallet-incentive-pool"
INCENTIVE_BUCKET = "01"
CHAIN_ID_RE = re.compile(r"^[a-z]+_[1-9][0-9]*-[1-9][0-9]*$")

# ignite needs these to build a chain; launch-config.yml deliberately has none of them,
# because its documented flow is publish-genesis -> gentx -> collect, not `chain init`.
IGNITE_REQUIRED = ["validation", "client", "validators", "build"]

# CSV bucket_id -> the account name used in launch-config.yml
SLUG = {"01": "adoption", "02": "ltr", "03": "foundation", "04": "grants",
        "05": "personnel", "06": "backers", "07": "founders", "09": "contingency",
        "10": "pubsec", "12": "nodeops"}
# NO genval1, AND NO SEPARATE pioneer1.  They were merged on 2026-09-01: a pioneer that is not a
# validator never proposes, so it never publishes an address and never carries a share.  There is
# now exactly ONE genesis_type=base row, and it funds qfi-pioneer1.
#
# This mapping was stale until 2026-09-04 and the effect was not subtle: --strict reported
# "account 'genval1': missing from launch-config" against a perfectly correct instance, so any
# build gated on this check would have failed every time.
# DERIVED FROM THE CONFIG, NOT HARDCODED HERE.  validators[0].name is the one place that says
# which account signs the gentx; buildscripts/init.sh and fill_launch_config.py both read it.  A
# constant in this file is a fourth copy of that name, and the drift is not theoretical: this
# check carried "genval1" for three days after the merge and reported
# "account 'genval1': missing from launch-config" against a perfectly correct instance.


# WHICH ACCOUNT DOES A CSV ROW BELONG TO?
#
# Not derivable from bucket_id alone -- buckets 01 and 12 hold two rows each -- so the
# discriminators are bucket_name for 01 and genesis_type for 12.
#
# An earlier version keyed on the genesis_address PLACEHOLDER, which worked only while the
# placeholders existed -- the moment real addresses were pasted in, every multi-row bucket
# silently mis-mapped and the verifier reported the wrong account's amount as wrong.  Key on
# fields that do not change when an address is filled in.
def account_of(row, slug, validator):
    if row["bucket_name"].strip() == "Wallet Incentive Pool":
        return "wallet-incentive-pool"
    if row["genesis_type"].strip() == "base":
        return validator
    return slug.get(row["bucket_id"])


def yaml_json(path, expr="."):
    out = subprocess.run(["yq", "-o=json", expr, str(path)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"verify_launch_config: yq failed on {path}: {out.stderr.strip()}")
    return json.loads(out.stdout)


def qdn_of(coin):
    """'960000000qdn' -> 960000000.  Rejects anything that is not whole qdn."""
    if not coin.endswith(AQDN_SUFFIX):
        return None
    body = coin[:-len(AQDN_SUFFIX)]
    return int(body) if body.isdigit() else None


class Report:
    def __init__(self):
        self.todo, self.err, self.warn, self.ok = [], [], [], []
    def unset(self, what, why):  self.todo.append((what, why))
    def bad(self, what, why):    self.err.append((what, why))
    def note(self, what, why):   self.warn.append((what, why))
    def good(self, what):        self.ok.append(what)


def check(cfg_path, csv_path, r):
    cfg = yaml_json(cfg_path)
    rows = list(csv.DictReader(open(csv_path, encoding="utf-8")))
    raw = Path(cfg_path).read_text()

    # ---- 1. unresolved placeholders, grouped by what kind of decision each is -------
    todos = sorted(set(re.findall(r"TODO_[A-Z0-9_]+", raw)))
    KIND = {
        "TODO_ADDR_": ("an ADDRESS you must generate in real custody "
                       "(hardware / multisig / MPC) -- HARD RULE 5 forbids generating "
                       "them here"),
        "TODO_AMOUNT_": "an AMOUNT that allocations.csv does not cover",
        "TODO_ENCLAVE_": ("an SGX MEASUREMENT -- the most security-critical value in the "
                          "file; the test values WORK, so this is the one most likely to "
                          "ship unchanged by accident"),
        "TODO_MIN_DEPOSIT": "governance deposit, set by TARGET FIAT VALUE not token count",
        "TODO_SUSPICIOUS": "AML reporting threshold",
        "TODO_JURISDICTION": "per-country AML threshold",
        "TODO_EXPIRY": "pricefeed expiry",
        "TODO_LAUNCH_PRICE": "launch price, needed to convert fiat-denominated fees",
        "TODO_CHAIN_ID": "chain id",
    }
    for t in todos:
        why = next((v for k, v in KIND.items() if t.startswith(k)), "unset")
        r.unset(t, why)

    # ---- 2. accounts match allocations.csv EXACTLY ----------------------------------
    vals = cfg.get("validators") or []
    validator = (vals[0] or {}).get("name") if vals else None
    if not validator:
        r.bad("validators[0].name", "missing -- cannot tell which account signs the gentx")
        validator = ""

    accounts = {a["name"]: a for a in cfg.get("accounts", [])}
    for row in rows:
        # bucket 01 and 12 each hold MORE THAN ONE row, so map by NAME, not by bucket_id.
        name = account_of(row, SLUG, validator)
        if name is None:
            r.bad(f"bucket {row['bucket_id']}", "no launch-config account name mapped")
            continue
        acct = accounts.get(name)
        if acct is None:
            r.bad(f"account '{name}'", f"missing from launch-config (bucket "
                                       f"{row['bucket_id']} {row['bucket_name']})")
            continue
        coins = acct.get("coins") or []
        got = qdn_of(coins[0]) if coins else None
        want = int(row["tokens_qdn"])
        if got is None:
            r.bad(f"account '{name}'", f"coins {coins} is not a whole-qdn amount")
        elif got != want:
            r.bad(f"account '{name}'",
                  f"has {got:,} qdn, allocations.csv says {want:,} "
                  f"(off by {got-want:+,}) -- the CSV is the source of truth")
        else:
            r.good(f"{name} = {want:,} qdn")

    named = {validator} | set(SLUG.values()) | {"wallet-incentive-pool"}
    for extra in sorted(set(accounts) - named):
        r.note(f"account '{extra}'",
               "not one of the ten buckets or the genesis validator -- it is extra "
               "supply unless allocations.csv accounts for it")

    # ---- 3. the total, as launch-config actually states it ---------------------------
    total = 0
    unknown = False
    for a in cfg.get("accounts", []):
        c = (a.get("coins") or [None])[0]
        v = qdn_of(c) if c else None
        if v is None:
            unknown = True
        else:
            total += v
    if unknown:
        r.note("accounts total", f"cannot be summed while amounts are unset "
                                 f"(known so far: {total:,} qdn)")
    elif total != TOTAL_QDN:
        r.bad("accounts total", f"sums to {total:,} qdn, expected {TOTAL_QDN:,} "
                                f"(off by {total-TOTAL_QDN:+,})")
    else:
        r.good(f"accounts total = {TOTAL_QDN:,} qdn")

    # ---- 4. things that make the chain refuse to run --------------------------------
    q = cfg.get("genesis", {}).get("app_state", {}).get("qadena", {})

    ipl = q.get("intervalPublicKeyIDList") or []
    pool = next((e for e in ipl if e.get("nodeID") == INCENTIVE_POOL_ID
                 and e.get("nodeType") == INCENTIVE_POOL_ID), None)
    if pool is None:
        r.bad("wallet-incentive-pool",
              f"no intervalPublicKeyIDList entry with nodeID == nodeType == "
              f"'{INCENTIVE_POOL_ID}'. x/qadena looks this up by HARDCODED constants and "
              f"PANICS without it -- the chain dies on its first wallet creation")
    else:
        poolacct = accounts.get("wallet-incentive-pool", {})
        if pool.get("pubKID") != poolacct.get("address"):
            r.bad("wallet-incentive-pool",
                  f"pubKID is {pool.get('pubKID')!r} but the wallet-incentive-pool account "
                  f"address is {poolacct.get('address')!r} -- the PubKID IS the account the "
                  f"chain debits for create_wallet incentives")
        else:
            r.good("wallet-incentive-pool -> its own account")

    wl = {e.get("address") for e in (q.get("scannedContractWhitelistList") or [])}
    missing = [n for n in sorted(named)
               if accounts.get(n, {}).get("address") not in wl]
    if missing:
        # NOT an error against the TEMPLATE: --apply fills one entry per account
        # when it renders, so duplicating placeholder addresses here would be noise that
        # then has to be kept in sync.  It IS an error in the rendered config, and
        # verify_genesis.py assertion 14 checks the built artifact.
        r.note("AML whitelist",
               f"{len(missing)} account(s) not listed here -- --apply fills one entry "
               f"per account when it renders, so this is expected in the TEMPLATE. It only "
               f"matters if you build the genesis by some other route; an account that is "
               f"neither a wallet nor listed is refused with code 1159 and cannot move a token")
    else:
        r.good(f"all {len(named)} accounts AML-whitelisted")

    if not (q.get("enclaveIdentityList") or []):
        r.bad("enclaveIdentityList", "empty -- the chain trusts no SGX measurement and "
                                     "no enclave can join")
    if not (q.get("publicKeyList") or []):
        r.bad("publicKeyList", "empty -- pioneer1 has no transaction/credential keys")

    # ---- 5. mint, and the chain id ---------------------------------------------------
    mint = cfg.get("genesis", {}).get("app_state", {}).get("mint", {}).get("params", {})
    lo, hi = mint.get("inflation_min"), mint.get("inflation_max")
    if lo != hi:
        r.bad("mint", f"inflation_min {lo} != inflation_max {hi}; the design is 1% FIXED")
    elif lo and float(lo) != 0.01:
        r.bad("mint", f"inflation is {lo}, expected 0.01")
    else:
        r.good(f"inflation fixed at {lo}")

    bpy = mint.get("blocks_per_year")
    if bpy:
        implied = 31_536_000 / int(bpy)
        if abs(implied - round(implied)) < 0.001 and implied in (1.0, 1.5, 2.0, 3.0, 5.0):
            r.note("blocks_per_year",
                   f"{bpy} implies exactly {implied:g}s -- that is a timeout_commit TARGET, "
                   f"not a measurement. Measure it (foundation_scripts/measure_block_time.sh); a "
                   f"chain faster than this over-mints for its whole life")
        else:
            r.good(f"blocks_per_year {bpy} (implies {implied:.3f}s)")

    cid = cfg.get("chain_id")
    if not cid or cid.startswith("TODO"):
        r.unset("chain_id", "unset")
    elif not CHAIN_ID_RE.match(cid):
        r.bad("chain_id", f"{cid!r} is not <name>_<eip155>-<epoch>. The EVM chain ID is "
                          f"PARSED from it and a mismatch fails SILENTLY")
    else:
        r.good(f"chain_id {cid}")

    # ---- 6. can ignite even build this? ---------------------------------------------
    absent = [k for k in IGNITE_REQUIRED if k not in cfg]
    if absent:
        r.bad("node runtime",
              f"missing top-level {', '.join(absent)}. These must be declared HERE with "
              f"mainnet values -- borrowing them from config/config.yml gives the launch "
              f"chain the devnet's validator name, a 10x bond, and a timeout_commit that "
              f"contradicts blocks_per_year")
    else:
        v = (cfg.get("validators") or [{}])[0]
        r.good(f"node runtime present (validator {v.get('name')}, bonded {v.get('bonded')})")
    return r


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # allocations.csv is HUMAN-OWNED and stays in tokenomics/ with the brief it belongs to;
    # this script lives in foundation_scripts/.  Resolve via the repo root, not via __file__'s
    # own directory -- that is what broke when the scripts moved out of tokenomics/.
    here = Path(__file__).resolve().parent
    tokenomics = here.parent / "tokenomics"
    ap.add_argument("--config", type=Path, default=here.parent / "config" / "launch-config.yml")
    ap.add_argument("--csv", type=Path, default=tokenomics / "allocations.csv")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 if anything is unset or wrong (mainnet gate)")
    args = ap.parse_args()

    r = check(args.config, args.csv, Report())

    if r.ok:
        print(f"OK ({len(r.ok)})")
        for x in r.ok:
            print(f"   {x}")
    if r.warn:
        print(f"\nNOTE ({len(r.warn)})")
        for what, why in r.warn:
            print(f"   {what}: {why}")
    if r.err:
        print(f"\nWRONG ({len(r.err)}) -- these disagree with allocations.csv or break the chain")
        for what, why in r.err:
            print(f"   {what}: {why}")
    if r.todo:
        print(f"\nSTILL UNSET ({len(r.todo)}) -- decisions only you can make")
        for what, why in r.todo:
            print(f"   {what}\n       {why}")

    ready = not r.err and not r.todo
    print(f"\n{'LAUNCH-READY' if ready else 'NOT launch-ready'}: "
          f"{len(r.err)} wrong, {len(r.todo)} unset")
    return 1 if (args.strict and not ready) else 0


if __name__ == "__main__":
    sys.exit(main())
