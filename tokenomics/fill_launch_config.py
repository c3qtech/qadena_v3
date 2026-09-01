#!/usr/bin/env python3
"""Fill the remaining placeholders in launch-config.yml and allocations.csv.

    ./fill_launch_config.py --template addresses.csv      # 1. what you must supply
    ./fill_launch_config.py --dev-keys addresses.csv      # 1b. DEV ONLY: make throwaway keys
    ./fill_launch_config.py --apply addresses.csv         # 2. paste them in
    ./fill_launch_config.py --enclave                     # 3. SGX ids, from the built enclave
    ./tokenomics/verify_launch_config.py --strict         # 4. gate

WHAT THIS DOES NOT DO: GENERATE PRODUCTION KEYS.  HARD RULE 5.  --dev-keys exists to
exercise the pipeline on a throwaway chain and refuses to run without --i-understand.

WHY AN ADDRESS IS ENOUGH FOR A BUCKET
-------------------------------------
A multisig address is a pure function of its member PUBLIC keys and the threshold, and is
derivable entirely offline -- `keys add --multisig` touches no chain and needs no private
key.  Genesis then writes a plain BaseAccount there with pub_key: null; the multisig's
LegacyAminoPubKey is presented at FIRST SIGNATURE.

So each signer generates in their own custody, exports a PUBKEY, and the address is
computed from those.  Nothing secret reaches the machine that builds genesis.

TWO ACCOUNTS ARE NOT LIKE THAT, and the difference matters operationally:

  qfi-pioneer1  ONE identity that is both the genesis validator and the genesis pioneer -- it
            signs the gentx, and on a devnet build buildscripts/setPubKAndPubKID.sh also
            resolves `qfi-pioneer1PubKID` from the KEYRING.  (A --mainnet-source build skips
            that substitution and takes the address and pubkey as literals instead.)

That one cannot be a cold multisig held elsewhere; the ten buckets can.

ORDER: addresses first, SGX measurements LAST.  uniqueID is the MRENCLAVE and changes on
ANY binary change, so it must be read from the exact build you intend to launch.
"""

import argparse, pathlib, csv, io, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAUNCH = ROOT / "config" / "launch-config.yml"
# NO ALLOC CONSTANT.  allocations.csv is human-owned (HARD RULE 1) and this tool used to
# rewrite it.  Nothing here may open it for writing; a path constant is the first step back
# to doing so, so it is deliberately absent.

# account -> (threshold as written in custody_final, what it is, placeholder in each file)
ACCOUNTS = [
    ("adoption",              "3of5", "Adoption Programs bucket",        "TODO_ADDR_ADOPTION",   "<01_MSIG_ADDR>"),
    ("wallet-incentive-pool", "3of5", "chain debits this per wallet",    "TODO_ADDR_WALLET_INCENTIVE_POOL", "<01_WIP_ADDR>"),
    ("ltr",                   "4of7", "Long-Term Reserve, 10yr FROZEN",  "TODO_ADDR_LTR",        "<02_MSIG_ADDR>"),
    ("foundation",            "3of5", "Foundation Treasury",             "TODO_ADDR_FOUNDATION", "<03_MSIG_ADDR>"),
    ("grants",                "3of5", "Builder & Partner Grants",        "TODO_ADDR_GRANTS",     "<04_MSIG_ADDR>"),
    ("personnel",             "3of5", "Personnel",                       "TODO_ADDR_PERSONNEL",  "<05_MSIG_ADDR>"),
    ("backers",               "3of5", "Early Backers Escrow",            "TODO_ADDR_BACKERS",    "<06_MSIG_ADDR>"),
    ("founders",              "3of5", "Founders Escrow",                 "TODO_ADDR_FOUNDERS",   "<07_MSIG_ADDR>"),
    ("contingency",           "2of5", "Contingency, LOW for speed",      "TODO_ADDR_CONTINGENCY","<09_MSIG_ADDR>"),
    ("pubsec",                "5of7", "Public Sector Programs",          "TODO_ADDR_PUBSEC",     "<10_MSIG_ADDR>"),
    ("nodeops",               "3of5", "Node Operations sponsor float",   "TODO_ADDR_NODEOPS",    "<12_MSIG_ADDR>"),
    # No genval1: merged into pioneer1 on 2026-09-01.  A pioneer that is not a validator never
    # proposes, so it never publishes an address and never carries a share.
    ("qfi-pioneer1",          "single", "NEEDS A REAL KEY (validator+pioneer)", "TODO_ADDR_QFI_PIONEER1", "<12_QFI_PIONEER1_ADDR>"),
]


def qadenad(*args):
    home = subprocess.run(["bash", "-lc", "echo ${QADENAHOME:-$HOME/qadena}"],
                          capture_output=True, text=True).stdout.strip()
    bin_ = Path(home) / "bin" / "qadenad"
    return subprocess.run([str(bin_), "--home", home, *args], capture_output=True, text=True)


def cmd_template(path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["name", "address", "threshold", "what_it_is", "how_to_derive"])
        for name, thr, what, _, _ in ACCOUNTS:
            how = ("qadenad keys add %s --multisig <m1,..,mN> --multisig-threshold %s "
                   "&& qadenad keys show %s -a" % (name, thr[0], name)) if thr != "single" \
                  else "a REAL single key that must exist in the genesis machine's keyring"
            w.writerow([name, "", thr, what, how])
    print(f"wrote {path} -- fill the `address` column, then --apply it")
    print("\nDerive each multisig from member PUBLIC keys, in real custody:")
    print("  qadenad keys add <name> --multisig k1,k2,k3,k4,k5 --multisig-threshold 3")
    print("  qadenad keys show <name> -a")
    print("\nNo private key needs to reach the machine that builds genesis -- except for")
    print("qfi-pioneer1, which does: it signs the gentx.")


def cmd_dev_keys(path, understood):
    if not understood:
        sys.exit("--dev-keys generates THROWAWAY keys and would be catastrophic for mainnet.\n"
                 "It exists only to exercise the pipeline on a disposable chain.\n"
                 "Re-run with --i-understand if that is what you want.")
    rows = []
    for name, thr, what, _, _ in ACCOUNTS:
        key = f"dev-{name}"
        if thr == "single":
            qadenad("keys", "add", key, "--keyring-backend", "test")
        else:
            n = int(thr.split("of")[1]); t = int(thr.split("of")[0])
            members = []
            for i in range(n):
                m = f"{key}-m{i+1}"
                qadenad("keys", "add", m, "--keyring-backend", "test")
                members.append(m)
            qadenad("keys", "add", key, "--multisig", ",".join(members),
                    "--multisig-threshold", str(t), "--keyring-backend", "test")
        out = qadenad("keys", "show", key, "-a", "--keyring-backend", "test")
        addr = out.stdout.strip()
        if not addr.startswith("qadena1"):
            sys.exit(f"could not derive an address for {name}: {out.stderr.strip()}")
        rows.append((name, addr, thr, what))
        print(f"  {name:<24} {thr:<7} {addr}")
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(["name", "address", "threshold", "what_it_is", "how_to_derive"])
        for name, addr, thr, what in rows:
            w.writerow([name, addr, thr, what, "DEV THROWAWAY KEY -- never for mainnet"])
    print(f"\nwrote {path}   (DEV keys, in the `test` keyring -- never use for mainnet)")


def render(supplied, pubkeys=None, generate=None):
    """Return launch-config.yml with every supplied address substituted.

    WRITES NOTHING.  This used to write config/launch-config.yml and tokenomics/allocations.csv
    in place, which was wrong twice over: launch-config.yml is a TEMPLATE -- filling it turns a
    tracked, reviewable file into one deployment's private state -- and allocations.csv is
    human-owned under HARD RULE 1, which exists precisely so tooling cannot touch it.

    The filled result is an INSTANCE: a build input for one chain, generated, gitignored, and
    handed to `init.sh --mainnet-source`.  Same source/artifact split as
    config/config.yml -> the root config.yml that ignite actually reads.
    """
    lc = LAUNCH.read_text()
    changed, unknown = 0, []

    # LET IGNITE MINT THIS ONE.  An ignite account given neither `address` nor `mnemonic` gets a
    # freshly generated key in the chain home keyring -- which is the only way a key can be there
    # when the gentx runs, because `ignite chain init` wipes that home first and anything
    # restored beforehand is destroyed.  So the address is not knowable until after the init.
    #
    # Every other reference to it therefore becomes "<name>PubKID", the placeholder
    # buildscripts/setPubKAndPubKID.sh resolves from the keyring AFTER the init -- the mechanism
    # the devnet has always used.  This keeps a mnemonic out of every file: nothing on disk ever
    # holds the key, and init.sh's assertion still fails the build if a placeholder survives.
    for name in (generate or []):
        todo = next((t for n, _, _, t, _ in ACCOUNTS if n == name), None)
        if not todo:
            sys.exit(f"--generate {name}: not an account in this config")
        before = lc
        lc = "\n".join(l for l in lc.splitlines()
                        if l.strip() != f'address: "{todo}"') + "\n"
        if lc == before:
            print(f"  WARNING: --generate {name}: no address line to drop")
        lc = lc.replace(todo, f"{name}PubKID")
        changed += 1

    # THE OTHER PLACEHOLDER CLASS.  TODO_ADDR_* are ours to fill; "<name>PubKID" and
    # "<name>PubK_pubk" were the BUILD's, resolved from the keyring by
    # buildscripts/setPubKAndPubKID.sh.  A --mainnet-source build skips that substitution on
    # purpose (it also exports a PRIVATE key, which no mainnet build may do) and then asserts
    # the genesis carries no unresolved placeholder -- so these have to be real values here.
    # Both are PUBLIC: an address and a pubkey, collected from whoever holds the key.
    for name, pk in (pubkeys or {}).items():
        a = supplied.get(name)
        if not a:
            continue
        if f"{name}PubKID" in lc:
            lc = lc.replace(f"{name}PubKID", a); changed += 1
        if f"{name}PubK_pubk" in lc:
            lc = lc.replace(f"{name}PubK_pubk", pk); changed += 1

    for name, _, _, todo, holder in ACCOUNTS:
        a = supplied.get(name)
        if not a:
            continue
        if todo in lc:
            lc = lc.replace(todo, a)
            changed += 1
        else:
            unknown.append(f"{name} ({todo} not in the template)")
    return lc, changed, unknown


def cmd_apply(path, out, generate=None):
    if not out:
        sys.exit("--apply needs --out FILE.\n"
                 "The filled config is a build INSTANCE, not an edit to the template:\n"
                 "  config/launch-config.yml   tracked template, keeps TODO_ADDR_ placeholders\n"
                 "  <--out>                    generated instance, gitignored, fed to\n"
                 "                             init.sh --mainnet-source\n"
                 "Keep --out OUTSIDE the repo if a --build-reproducible may run: that path does\n"
                 "`git checkout -f && git clean -fd` and deletes untracked files.")
    supplied, pubkeys = {}, {}
    for r in csv.DictReader(open(path, encoding="utf-8")):
        a = (r.get("address") or "").strip()
        if a:
            if not a.startswith("qadena1"):
                sys.exit(f"{r['name']}: {a!r} is not a qadena address")
            supplied[r["name"].strip()] = a
        pk = (r.get("pubkey") or "").strip()
        if pk:
            pubkeys[r["name"].strip()] = pk
    if not supplied:
        sys.exit(f"{path} has no addresses filled in")

    lc, changed, unknown = render(supplied, pubkeys, generate)
    missing = [n for n, *_ in ACCOUNTS if n not in supplied]

    outp = pathlib.Path(out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(lc)
    print(f"wrote {outp}  ({changed} address(es) substituted)")
    print(f"  template config/launch-config.yml is UNCHANGED, still holding placeholders")
    for u in unknown:
        print(f"  WARNING: {u}")
    if missing:
        print(f"  still unset ({len(missing)}): {', '.join(missing)}")
    # report BOTH placeholder classes -- a surviving PubKID fails init.sh --mainnet-source
    left = re.findall(r"TODO_ADDR_[A-Z0-9_]+", lc)
    # STRIP COMMENTS FIRST.  YAML comments never reach genesis.json, so a placeholder named
    # only in prose is not a defect -- flagging it trains the reader to ignore this warning.
    body = "\n".join(l for l in lc.splitlines() if not l.lstrip().startswith("#"))
    bl = sorted({m for m in re.findall(r"[A-Za-z0-9_-]*(?:PubKID|PubK_pubk)", body)
                 if m not in ("PubKID", "setPubKAndPubKID")})
    if bl:
        print(f"  {len(bl)} build placeholder(s) unresolved (add a `pubkey` column): {', '.join(bl)}")
    if left:
        print(f"  {len(set(left))} placeholder(s) remain in the instance: {', '.join(sorted(set(left)))}")


def cmd_enclave_test_fleet():
    """Write the TEST-FLEET enclave identity: the same placeholders config/config.yml uses.

    On a debug-enclave fleet (M1-M4 are aarch64 with no SGX) there is no MRENCLAVE to read.
    The established mechanism is that genesis carries `test-unique-id` / `test-signer-id`
    and buildscripts/build_enclave.sh REWRITES uniqueID and signerID in the generated
    genesis.json with the ids the build actually produced.  productID it does not touch.

    So these three strings are correct for a test fleet and CATASTROPHIC for mainnet -- the
    chain would trust a measurement anyone can reproduce.
    """
    lc = LAUNCH.read_text()
    lc = (lc.replace("TODO_ENCLAVE_UNIQUE_ID", "test-unique-id")
            .replace("TODO_ENCLAVE_SIGNER_ID", "test-signer-id")
            .replace("TODO_ENCLAVE_PRODUCT_ID", "test-product-id"))
    marker = ("      # !! TEST-FLEET VALUES !!  These are the placeholders config/config.yml uses;\n"
              "      # buildscripts/build_enclave.sh rewrites uniqueID and signerID in the GENERATED\n"
              "      # genesis.json with the ids the debug build produced.  They are correct for a\n"
              "      # debug fleet (M1-M4 have no SGX) and MUST NOT reach mainnet: a real launch\n"
              "      # needs the MRENCLAVE of the exact SGX build, read with\n"
              "      #     qadenad query qadena enclave-measurement\n"
              "      enclaveIdentityList:")
    lc = lc.replace("      enclaveIdentityList:", marker, 1)
    LAUNCH.write_text(lc)
    print("  uniqueID  test-unique-id   (build_enclave.sh rewrites this)")
    print("  signerID  test-signer-id   (build_enclave.sh rewrites this)")
    print("  productID test-product-id  (not rewritten -- assign a real one for mainnet)")
    print("\n  written, marked TEST-FLEET ONLY in launch-config.yml")
    return 0


def cmd_enclave():
    out = qadenad("query", "qadena", "enclave-measurement")
    if out.returncode != 0:
        sys.exit(f"could not read the enclave measurement: {out.stderr.strip()}\n"
                 f"Run this against a node running the EXACT build you intend to launch.")
    vals = {}
    for line in out.stdout.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            vals[k.strip()] = v.strip().strip('"')
    uid, sid, pid = vals.get("uniqueID", ""), vals.get("signerID", ""), vals.get("productID", "")
    print(f"  uniqueID  {uid}\n  signerID  {sid}\n  productID {pid or '(empty -- you must assign one)'}")
    if uid.startswith("unique") or sid.startswith("signer"):
        print("\n  REFUSING to write: these are DEBUG-enclave ids, not SGX measurements.")
        print("  launch-config.yml calls this the most security-critical entry in the file,")
        print("  and the test values WORK -- which is exactly how they get shipped by accident.")
        print("  Build the real SGX enclave and re-run against a node running it.")
        return 1
    if not pid:
        print("\n  productID is empty. It is ASSIGNED, not derived -- decide it, then set it by hand.")
        return 1
    lc = LAUNCH.read_text()
    lc = (lc.replace("TODO_ENCLAVE_UNIQUE_ID", uid)
            .replace("TODO_ENCLAVE_SIGNER_ID", sid)
            .replace("TODO_ENCLAVE_PRODUCT_ID", pid))
    LAUNCH.write_text(lc)
    print("\n  written to launch-config.yml")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--template", metavar="FILE")
    ap.add_argument("--dev-keys", metavar="FILE")
    ap.add_argument("--i-understand", action="store_true")
    ap.add_argument("--apply", metavar="FILE")
    ap.add_argument("--generate", metavar="NAME", action="append",
                    help="leave this account for ignite to mint (no address, no mnemonic); "
                         "its references become <name>PubKID for post-init substitution")
    ap.add_argument("--out", metavar="FILE",
                    help="where to write the filled INSTANCE (required with --apply)")
    ap.add_argument("--enclave", action="store_true")
    ap.add_argument("--test-fleet", action="store_true",
                    help="with --enclave: write the debug-fleet placeholders instead of "
                         "reading an SGX measurement. NEVER for mainnet")
    a = ap.parse_args()
    if a.template:  cmd_template(a.template); return 0
    if a.dev_keys:  cmd_dev_keys(a.dev_keys, a.i_understand); return 0
    if a.apply:     cmd_apply(a.apply, a.out, a.generate); return 0
    if a.enclave:   return cmd_enclave_test_fleet() if a.test_fleet else cmd_enclave()
    ap.print_help(); return 1


if __name__ == "__main__":
    sys.exit(main())
