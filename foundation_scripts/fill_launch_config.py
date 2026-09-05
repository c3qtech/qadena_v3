#!/usr/bin/env python3
"""Fill the remaining placeholders in launch-config.yml and allocations.csv.

    ./fill_launch_config.py --template addresses.csv      # 1. what you must supply
    ./fill_launch_config.py --dev-keys addresses.csv      # 1b. DEV ONLY: make throwaway keys
    ./fill_launch_config.py --apply addresses.csv         # 2. paste them in
    ./fill_launch_config.py --enclave                     # 3. SGX ids, from the built enclave
    ./foundation_scripts/verify_launch_config.py --strict         # 4. gate

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
ALLOC  = ROOT / "tokenomics" / "allocations.csv"
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
        # REAL NAMES, NOT dev- PREFIXES.  The brief's LATE ARRIVAL section is explicit that at
        # genesis "almost nobody's address is known": the buckets exist, the members arrive
        # later, and until they do the FOUNDER holds every member key.  These are not stand-ins
        # for someone else's custody -- they ARE the day-one custody -- so they carry the names
        # operations will use.  The --i-understand guard still marks them as generated-by-script:
        # what makes a key unfit for mainnet is how it was minted, not what it is called.
        key = name
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



# ---------------------------------------------------------------------------------------------
# AMOUNTS COME FROM allocations.csv, WHICH IS THE AUTHORITY.
#
# launch-config.yml carries its own `coins:` values, and until now nothing reconciled the two --
# only verify_launch_config.py noticed afterwards, if anyone ran it.  Editing the CSV therefore
# changed nothing about the chain that got built.  Applying them here makes the CSV load-bearing on
# the path that is actually used.
#
# THE JOIN IS ON FIELDS THAT SURVIVE FILLING IN AN ADDRESS.  An earlier renderer (build_config.py,
# removed 2026-09-04) keyed on the genesis_address PLACEHOLDER, and recorded what that cost: the
# moment real addresses were pasted in, every multi-row bucket silently mis-mapped and the verifier
# reported the wrong account's amount as wrong.  bucket_id alone is not enough either -- buckets 01 and 12 hold two
# rows each -- so the discriminators are bucket_name for 01 and genesis_type for 12.
SLUG = {"01": "adoption", "02": "ltr", "03": "foundation", "04": "grants", "05": "personnel",
        "06": "backers", "07": "founders", "09": "contingency", "10": "pubsec", "12": "nodeops"}


def account_of(row):
    """Which launch-config account does this CSV row fund?  None if it funds nothing."""
    if row["bucket_name"].strip() == "Wallet Incentive Pool":
        return "wallet-incentive-pool"
    if row["genesis_type"].strip() == "base":
        # THE ONLY `base` ROW.  There were two once -- pioneer1 and genval1 -- and genval1 was
        # merged into the pioneer on 2026-09-01 because a pioneer that is not a validator never
        # proposes, so it never publishes an address and never carries a share.  The removed
        # renderer still branched on `stakes == self-bond` to tell them apart and returned
        # "genval1", an account that no longer exists anywhere -- which is one reason it went.
        return "qfi-pioneer1"
    return SLUG.get(row["bucket_id"].strip())


def csv_amounts(path=ALLOC):
    """{account name: whole qdn} from allocations.csv."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = account_of(row)
            if not name:
                continue
            if name in out:
                sys.exit(f"allocations.csv maps two rows to '{name}' -- the join is ambiguous")
            out[name] = int(row["tokens_qdn"])
    return out


def csv_addresses(path=ALLOC):
    """{account name: genesis_address} from allocations.csv, placeholders included.

    Same join as csv_amounts -- account_of, never the address itself -- so this keeps working
    once step 3 replaces the placeholders with real keys.
    """
    out = {}
    with open(path, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            name = account_of(row)
            if name:
                out[name] = (row["genesis_address"] or "").strip()
    return out


def is_placeholder(a):
    return a.startswith("<") and a.endswith(">")


def cross_check(supplied, path=ALLOC):
    """addresses.csv vs allocations.csv, for every account both files name.

    WHY THIS IS FATAL AND NOT A WARNING.  These two files are derived from different things --
    one from a keyring, one from a human's paste -- and nothing else compares them.  --apply
    takes ADDRESSES from addresses.csv and AMOUNTS from allocations.csv, so if they disagree
    about which key holds a bucket, the instance is internally consistent, the genesis builds,
    every later assertion passes, and the wrong key controls the money.  verify_genesis
    assertion 5 is the only other thing that could notice, and it is exactly what
    --allow-placeholders relaxes on the test path.

    A mismatch is never a legitimate state: either the CSV was filled from a stale
    addresses.csv, or the keys were re-derived after step 3.  Both mean stop and reconcile.
    """
    try:
        alloc = csv_addresses(path)
    except (OSError, KeyError):
        return          # csv_amounts reports a broken/missing allocations.csv properly
    wrong, placeheld = [], []
    for name, addr in sorted(supplied.items()):
        want = alloc.get(name)
        if want is None:
            continue                       # funds nothing in allocations.csv
        if is_placeholder(want):
            placeheld.append(name)
        elif want != addr:
            wrong.append((name, want, addr))
    if wrong:
        print("ADDRESS MISMATCH -- allocations.csv and addresses.csv disagree:", file=sys.stderr)
        for name, want, got in wrong:
            print(f"  {name}\n      allocations.csv : {want}\n      addresses.csv   : {got}",
                  file=sys.stderr)
        sys.exit("\nNothing written.  One of the two files is stale -- reconcile them before\n"
                 "rendering.  If the keys were re-derived, redo step 3 from the new\n"
                 "addresses.csv; if addresses.csv is the stale one, re-run derive_launch_keys.sh.")
    if placeheld:
        print(f"  NOTE: {len(placeheld)} account(s) still hold a PLACEHOLDER address in "
              f"allocations.csv,")
        print(f"        so they could not be cross-checked: {', '.join(placeheld)}")
        print(f"        The instance is still valid -- addresses come from addresses.csv, not "
              f"from that column.")
        print(f"        But init.sh --mainnet-source WILL REFUSE until step 3 fills them "
              f"(assertion 13).")
    elif supplied:
        print(f"  cross-checked {len(supplied) - len(placeheld)} address(es) against "
              f"allocations.csv: all agree")


MAINNET_CHAIN_ID = "qadena_482-1"


def set_chain_id(lc, chain_id):
    """Rewrite every chain_id in the instance, having first checked the node can parse it.

    THE FORMAT IS LOad-BEARING AND FAILS SILENTLY.  cmd/qadenad/cmd/commands.go derives the EVM
    chain ID by splitting the cosmos chain-id on "_" then "-", and EVERY failure path is a bare
    `return`: a malformed id leaves EVMChainID unset, with no error at init, no error at start,
    and the mismatch surfacing later as transactions that will not verify.  So refuse here,
    where there is something to read.

    Two places carry it -- the top-level key and the nested one that must match it -- and a
    genesis where they disagree is a chain whose client talks to the wrong network.
    """
    m = re.fullmatch(r"([A-Za-z][A-Za-z0-9]*)_(\d+)-(\d+)", chain_id)
    if not m:
        sys.exit(f"--chain-id {chain_id!r} is not <name>_<eip155>-<epoch> (e.g. qadena_4824-1).\n"
                 f"qadenad PARSES the EVM chain id out of this string and returns silently when\n"
                 f"it cannot, leaving EVMChainID unset.  Nothing would tell you at build time.")
    if int(m.group(2)) == 0:
        sys.exit(f"--chain-id {chain_id!r}: the EIP-155 number may not be 0 -- qadenad treats a\n"
                 f"parsed 0 as a parse failure and leaves EVMChainID unset.")
    lc, n = re.subn(r'^(\s*)chain_id: ".*?"', lambda mm: f'{mm.group(1)}chain_id: "{chain_id}"',
                    lc, flags=re.M)
    if n < 2:
        print(f"  WARNING: rewrote only {n} chain_id line(s); the template normally has 2")
    return lc, n


def apply_amounts(lc, amounts):
    """Set each account's `coins:` from the CSV.  Line-based, so the file's comments survive.

    Parsing and re-dumping the YAML would lose them, and in this file the prose explaining WHY a
    value was chosen is the most valuable thing in it.
    """
    out, cur, changed, seen = [], None, 0, set()
    for line in lc.splitlines():
        m = re.match(r'^(\s*)- name:\s*(\S+)\s*$', line)
        if m:
            cur = m.group(2)
        elif re.match(r'^\s*[a-z_]+:', line) and not line.startswith(" "):
            cur = None                      # left the accounts block entirely
        if cur and cur in amounts and re.match(r'^\s*coins:', line):
            indent = line[:len(line) - len(line.lstrip())]
            want = f'{indent}coins: ["{amounts[cur]}qdn"]'
            if line.rstrip() != want:
                changed += 1
            out.append(want)
            seen.add(cur)
            cur = None                      # one coins line per account
            continue
        out.append(line)
    missing = sorted(set(amounts) - seen)
    if missing:
        sys.exit("allocations.csv funds accounts with no `coins:` line in launch-config.yml: "
                 + ", ".join(missing))
    return "\n".join(out) + "\n", changed


def validator_name(lc):
    """validators[0].name from the template text -- the account that signs the gentx."""
    inv = False
    for line in lc.splitlines():
        if re.match(r'^validators:', line):
            inv = True
            continue
        if inv and re.match(r'^[a-z]', line):
            break
        if inv:
            m = re.match(r'^\s*- name:\s*(\S+)\s*$', line)
            if m:
                return m.group(1)
    return None

def render(supplied, pubkeys=None, generate=None, test_gov=False, amounts=None,
           chain_id=None, zero_incentives=False):
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

    # AMOUNTS FIRST, BEFORE ANY ADDRESS SUBSTITUTION.  The join reads allocations.csv, whose rows
    # are identified by bucket_id/name/type -- fields an address substitution does not touch --
    # so order does not actually matter here, but doing it first keeps the failure (a funded
    # account with no `coins:` line) separate from address problems.
    if amounts is not False:
        amt = amounts if isinstance(amounts, dict) else csv_amounts()
        lc, n = apply_amounts(lc, amt)
        if n:
            print(f"  {n} amount(s) set from {ALLOC.name}")

    # LET IGNITE MINT THIS ONE.  An ignite account given neither `address` nor `mnemonic` gets a
    # freshly generated key in the chain home keyring -- which is the only way a key can be there
    # when the gentx runs, because `ignite chain init` wipes that home first and anything
    # restored beforehand is destroyed.  So the address is not knowable until after the init.
    #
    # Every other reference to it therefore becomes "<name>PubKID", the placeholder
    # buildscripts/setPubKAndPubKID.sh resolves from the keyring AFTER the init -- the mechanism
    # the devnet has always used.  This keeps a mnemonic out of every file: nothing on disk ever
    # holds the key, and init.sh's assertion still fails the build if a placeholder survives.
    # THE VALIDATOR IS GENERATED BY DEFAULT, because on this path there is no other correct
    # answer.  ignite must have a SIGNING KEY in the chain home to sign the gentx, and it only
    # creates one from a `mnemonic:`.  An account left with an `address:` gets funded with no key,
    # so `ignite chain init` fails at the gentx -- AFTER `rm -rf $QADENAHOME`, with an error about
    # signing rather than about the flag nobody passed.
    #
    # Stripping the address is also what makes init.sh's hidden prompt fire, which is how the
    # sealed mnemonic reaches ignite without ever being written to a file.
    #
    # --no-generate opts out, for a genesis whose validator signs somewhere else.
    if generate is None:
        v = validator_name(lc)
        if v and any(n == v for n, *_ in ACCOUNTS):
            generate = [v]
            print(f"  --generate defaulted to '{v}' (validators[0].name); --no-generate to opt out")
        elif v:
            print(f"  WARNING: validators[0].name is '{v}', which is not an account here -- "
                  f"nothing generated")

    generated = set(generate or [])
    for name in generated:
        todo = next((t for n, _, _, t, _ in ACCOUNTS if n == name), None)
        if not todo:
            sys.exit(f"'{name}' is not an account in this config -- cannot generate it")
        before = lc
        lc = "\n".join(l for l in lc.splitlines()
                        if l.strip() != f'address: "{todo}"') + "\n"
        if lc == before:
            print(f"  WARNING: {name}: no address line to drop (already generated?)")
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
        elif name not in generated:
            # Not a warning for a generated account: the block above deliberately renamed its
            # TODO_ADDR_ to <name>PubKID, so of course it is no longer in the text.  Warning
            # there sent operators looking for a template bug that did not exist.
            unknown.append(f"{name} ({todo} not in the template)")
    # TEST-ONLY GOVERNANCE TIMINGS -- INSTANCE ONLY, AND THE ONE DEVIATION THAT IS DEFENSIBLE.
    #
    # The launch window's periods are 72h voting / 6h expedited.  Correct for mainnet, and they
    # make a test loop impossible: anything gated on a proposal (whitelisting a treasury so it can
    # fund the suites, registering an enclave measurement, a param change) blocks for hours.
    #
    # WHY THIS DEVIATION AND NOT THE OTHERS.  Every other difference between a test genesis and
    # the real one has bitten us: a missing evm section, a missing priv_validator_laddr, a
    # devnet-sized funding default.  Those were all things the chain DEPENDS ON to behave
    # correctly, so testing without them tested the wrong chain.  Voting periods are not that:
    # they are governance-updatable at any time, they change no consensus or custody property,
    # and every rule a proposal must satisfy -- quorum, threshold, veto, deposit -- is untouched.
    # What shortens is only the wait.
    #
    # It is still a deviation.  Never render an instance for a real launch with this flag.
    # A SHORT CLOCK AND THE MAINNET ID ARE NEVER BOTH RIGHT.  --test-gov-timings produces a
    # chain where anything passes in five minutes; the mainnet chain-id is what makes a
    # transaction signed on it replayable against mainnet.  Together they are a testnet wearing
    # the production network's identity, which is the one combination worth refusing outright.
    if test_gov and (chain_id or MAINNET_CHAIN_ID) == MAINNET_CHAIN_ID:
        sys.exit(f"--test-gov-timings with chain-id {MAINNET_CHAIN_ID} (the MAINNET id) is refused.\n"
                 f"Pass --chain-id for the network you are actually building, e.g.\n"
                 f"    --chain-id qadena_4824-1     (testnet)\n"
                 f"Addresses derive identically on every EVM chain and EIP-155 replay protection\n"
                 f"IS the chain id, so a short-clock chain sharing mainnet's id makes anything\n"
                 f"signed there replayable against mainnet.")
    if chain_id:
        lc, _ = set_chain_id(lc, chain_id)
        changed += 1
    # ZEROED WALLET INCENTIVES -- TEST ONLY, AND THE REASON IS EVIDENCE, NOT THRIFT.
    #
    # The chain endows every new wallet: 500 QDN to a real one, 50 to a transparent ephemeral.
    # That endowment is a SECOND source of funds, so a wallet whose fee grant is missing or points
    # at the wrong granter still transacts -- it just pays for itself.  Every such bug then looks
    # exactly like success.
    #
    # Zeroing them is what makes a green run mean something: with no endowment, a transaction can
    # only succeed if a grant carried it.  It is also what produced the only trustworthy cost
    # figures we have (352.016 QDN per onboarding), since nothing was subsidised.
    #
    # The DENOM stays "qdn".  x/qadena calls sdk.NormalizeCoin on these params, which is a no-op on
    # aqdn -- so writing aqdn here would pay 10^18 times too little.  verify_genesis assertion 8
    # enforces that, and zero-with-the-right-denom passes it.
    if zero_incentives:
        _INC = ("create_wallet_incentive", "create_wallet_transparent_incentive",
                "create_ephemeral_wallet_incentive", "create_ephemeral_wallet_transparent_incentive")
        out, arm, done = [], None, 0
        for line in lc.splitlines():
            st = line.strip().rstrip(":")
            if st in _INC:
                arm = st
            elif arm and st.startswith("amount:"):
                indent = line[:len(line) - len(line.lstrip())]
                line = f'{indent}amount: "0"'
                arm = None; done += 1
            elif arm and not st.startswith(("amount", "denom")):
                arm = None
            out.append(line)
        lc = "\n".join(out) + "\n"
        print(f"  --zero-incentives: {done}/4 wallet incentives set to 0 (denoms untouched)")
        if done != 4:
            print(f"  WARNING: expected 4, changed {done} -- check the template's param names")
        changed += 1

    if test_gov:
        lc = re.sub(r'^(\s*)voting_period: ".*?"',            r'\1voting_period: "300s"',            lc, count=1, flags=re.M)
        lc = re.sub(r'^(\s*)expedited_voting_period: ".*?"',  r'\1expedited_voting_period: "30s"',   lc, count=1, flags=re.M)
        lc = re.sub(r'^(\s*)max_deposit_period: ".*?"',       r'\1max_deposit_period: "300s"',       lc, count=1, flags=re.M)
        changed += 1

    return lc, changed, unknown


def cmd_apply(path, out, generate=None, test_gov=False, chain_id=None, zero_incentives=False):
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

    # BEFORE ANYTHING IS WRITTEN.  A mismatch here means the wrong key would hold a bucket.
    cross_check(supplied)

    lc, changed, unknown = render(supplied, pubkeys, generate, test_gov, chain_id=chain_id,
                                  zero_incentives=zero_incentives)
    missing = [n for n, *_ in ACCOUNTS if n not in supplied]

    outp = pathlib.Path(out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(lc)
    print(f"wrote {outp}  ({changed} substitution(s))")
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
    # NO --generate FLAG.  It only ever named validators[0].name, which this now reads for
    # itself, and passing the wrong name silently produced an instance whose validator had an
    # address -- so no prompt, no mnemonic, and a gentx that cannot be signed.  One fewer thing
    # to get right.
    ap.add_argument("--zero-incentives", action="store_true",
                    help="set the four wallet incentives to 0 in the INSTANCE. TEST ONLY: the "
                         "endowment is a second funding source that makes a missing fee grant "
                         "look like success. Denoms are left as qdn (NormalizeCoin needs them).")
    ap.add_argument("--chain-id", metavar="ID",
                    help="rewrite chain_id in the instance, e.g. qadena_4824-1 for a testnet. "
                         "Must be <name>_<eip155>-<epoch>: qadenad parses the EVM chain id out "
                         "of it and fails SILENTLY if it cannot. Required with --test-gov-timings.")
    ap.add_argument("--no-generate", action="store_true",
                    help="do not strip any account's address, not even the validator's. "
                         "Only for a genesis whose validator signs its gentx elsewhere")
    ap.add_argument("--test-gov-timings", action="store_true",
                    help="INSTANCE ONLY: shorten gov voting to 300s/30s so proposal-gated tests "
                         "can finish.  Changes no rule, only the wait.  NEVER for a real launch.")
    ap.add_argument("--out", metavar="FILE",
                    help="where to write the filled INSTANCE (required with --apply)")
    ap.add_argument("--enclave", action="store_true")
    ap.add_argument("--test-fleet", action="store_true",
                    help="with --enclave: write the debug-fleet placeholders instead of "
                         "reading an SGX measurement. NEVER for mainnet")
    a = ap.parse_args()
    if a.template:  cmd_template(a.template); return 0
    if a.dev_keys:  cmd_dev_keys(a.dev_keys, a.i_understand); return 0
    if a.apply:     cmd_apply(a.apply, a.out, [] if a.no_generate else None,
                              a.test_gov_timings, a.chain_id, a.zero_incentives); return 0
    if a.enclave:   return cmd_enclave_test_fleet() if a.test_fleet else cmd_enclave()
    ap.print_help(); return 1


if __name__ == "__main__":
    sys.exit(main())
