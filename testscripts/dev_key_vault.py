#!/usr/bin/env python3
"""Export/restore the DEV throwaway keys so they survive `init.sh`.

WHY THIS EXISTS
---------------
buildscripts/init.sh line 164 runs `rm -rf $QADENAHOME`, and the keyring lives INSIDE it
($QADENAHOME/keyring-test).  So every dev key -- the bucket multisigs and their members --
is destroyed the moment the chain is re-initialised.  Without a vault the genesis you just
built references addresses that can never be signed for again: funded and unspendable.

Adding a node or running the regression needs those signers back, so the vault has to live
OUTSIDE $QADENAHOME and be restorable in one command.

WHAT IS STORED
--------------
This build has no `keys import-hex`, so an unarmored hex dump cannot be restored.  What does
round-trip is the ARMORED export (`keys export` -> `keys import`), which is passphrase-
encrypted -- verified by round-trip test before this tool was written.

  single / member keys   the armored private key blob
  multisig keys          NOT a secret: threshold + member names.  A multisig has no private
                         material of its own, it is derived from its members' pubkeys, so it
                         is rebuilt with `keys add --multisig` after the members are back.

Addresses are recorded alongside so a restore can be VERIFIED rather than assumed -- the
whole point is that the address in genesis still resolves to a key you hold.

THESE ARE THROWAWAY KEYS.  The vault is still secret material: it restores signing authority
over every genesis bucket on the test chain.  Keep it out of git.
"""
import argparse, json, os, shutil, subprocess, sys, socket
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def find_qadenad():
    """Locate a usable binary.  $qadenabin FIRST, but it is not always there: init.sh restores
    this vault immediately after `rm -rf $QADENAHOME`, and $qadenabin lives INSIDE that home --
    so at restore time the installed binary has just been deleted and build.sh has not run yet
    (it runs after `ignite chain init`, which is the very step that needs the key).  The staged
    build at the repo root is what exists in that window."""
    cands = []
    binp = os.environ.get("qadenabin")
    if binp:
        cands.append(Path(binp) / "qadenad")
    cands += [Path.home() / "qadena" / "bin" / "qadenad", REPO / "qadenad"]
    w = shutil.which("qadenad")
    if w:
        cands.append(Path(w))
    for c in cands:
        if c.exists() and os.access(c, os.X_OK):
            return c
    sys.exit("no qadenad binary found (looked in $qadenabin, ~/qadena/bin, the repo root, "
             "and $PATH).  Build one first, or source scripts/setup_env.sh.")


def qadenad(*args, stdin=None):
    home = os.environ.get("QADENAHOME") or str(Path.home() / "qadena")
    exe = find_qadenad()
    Path(home).mkdir(parents=True, exist_ok=True)
    cmd = [str(exe), "--home", home, "--keyring-backend", "test", *args]
    return subprocess.run(cmd, input=stdin, capture_output=True, text=True)


def read_passphrase(path):
    if not path:
        sys.exit("--passphrase-file is required: the armored export is encrypted, and a\n"
                 "passphrase typed interactively cannot be re-used by a restore script.")
    p = Path(path)
    if not p.exists():
        sys.exit(f"passphrase file {p} does not exist")
    pw = p.read_text().strip()
    if len(pw) < 8:
        sys.exit("passphrase must be at least 8 characters")
    return pw


def list_keys(prefix):
    r = qadenad("keys", "list", "--output", "json")
    if r.returncode != 0:
        sys.exit(f"keys list failed: {r.stderr.strip()}")
    return [k for k in json.loads(r.stdout) if k["name"].startswith(prefix)]


def cmd_export(out, passphrase_file, prefix, include, exclude):
    """Export a SUBSET.  Splitting matters: the build host needs exactly one key -- the
    pioneer identity that signs the gentx and is handed to InitEnclave.  The eleven bucket
    multisigs are genesis ADDRESSES; no key of theirs is ever needed to build a chain.  Keeping
    them in the same file as the one key the build host must load means the build host loads
    all of them, which is the opposite of what the custody split is for."""
    pw = read_passphrase(passphrase_file)
    keys = list_keys(prefix)
    if include:
        want = set(include)
        # a multisig's members come with it -- it cannot be rebuilt without them
        for k in list(keys):
            if k["name"] in want and k["type"] == "multi":
                pub = json.loads(k["pubkey"]) if isinstance(k["pubkey"], str) else k["pubkey"]
                want |= {f'{k["name"]}-m{i+1}' for i in range(len(pub["public_keys"]))}
        keys = [k for k in keys if k["name"] in want]
    if exclude:
        drop = set(exclude)
        for k in list(keys):
            if k["name"] in drop and k["type"] == "multi":
                pub = json.loads(k["pubkey"]) if isinstance(k["pubkey"], str) else k["pubkey"]
                drop |= {f'{k["name"]}-m{i+1}' for i in range(len(pub["public_keys"]))}
        keys = [k for k in keys if k["name"] not in drop]
    if not keys:
        sys.exit(f"no keys with prefix {prefix!r} in the keyring -- nothing to vault")

    singles = [k for k in keys if k["type"] != "multi"]
    multis  = [k for k in keys if k["type"] == "multi"]
    entries, failed = [], []

    for k in singles:
        # export prompts for the passphrase TWICE (enter + confirm)
        r = qadenad("keys", "export", k["name"], stdin=f"{pw}\n{pw}\n")
        armor = r.stdout.strip()
        if "BEGIN TENDERMINT PRIVATE KEY" not in armor:
            failed.append((k["name"], r.stderr.strip()[:120])); continue
        entries.append({"name": k["name"], "kind": "single",
                        "address": k["address"], "armor": armor})

    for k in multis:
        # member names by convention, then VERIFY the rebuilt composition matches the
        # recorded threshold -- a silently wrong member list would restore a different address.
        pub = json.loads(k["pubkey"]) if isinstance(k["pubkey"], str) else k["pubkey"]
        thr = int(pub["threshold"]); n = len(pub["public_keys"])
        members = [f"{k['name']}-m{i+1}" for i in range(n)]
        have = {e["name"] for e in entries}
        missing = [m for m in members if m not in have]
        if missing:
            failed.append((k["name"], f"members not exported: {', '.join(missing)}")); continue
        entries.append({"name": k["name"], "kind": "multisig", "address": k["address"],
                        "threshold": thr, "members": members})

    if failed:
        for n, e in failed:
            print(f"  FAILED {n}: {e}", file=sys.stderr)
        sys.exit(f"{len(failed)} key(s) could not be vaulted; refusing to write a partial vault")

    vault = {
        "_warning": "DEV THROWAWAY KEYS. Never mainnet. Restores signing authority over every "
                    "genesis bucket on the test chain -- keep out of git.",
        "_source_host": socket.gethostname(),
        "_restore": "testscripts/dev_key_vault.py import --in <this file> --passphrase-file <f>",
        "prefix": prefix,
        "keys": entries,
    }
    p = Path(out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(vault, indent=2) + "\n")
    os.chmod(p, 0o600)
    print(f"vaulted {len(entries)} key(s) ({len(singles)} secret, {len(multis)} multisig) -> {p}")
    print(f"  mode 0600.  This file survives `init.sh`; $QADENAHOME does not.")


def local_name(vault_name, strip):
    """The name to restore UNDER.  ignite looks a validator's key up by the ACCOUNT name in
    config.yml (`qfi-pioneer1`), while the vault holds it prefixed (`dev-qfi-pioneer1`) to keep
    throwaway keys obviously throwaway in a shared keyring.  Restoring without stripping puts
    the key in under a name nothing looks for, and the gentx fails with the key sitting right
    there."""
    if strip and vault_name.startswith(strip):
        return vault_name[len(strip):]
    return vault_name


def cmd_import(src, passphrase_file, strip=None, include=None):
    pw = read_passphrase(passphrase_file)
    vault = json.loads(Path(src).read_text())
    entries = vault["keys"]

    # RESTORE ONLY WHAT THIS MACHINE NEEDS.  A vault holding every bucket's signing authority
    # should not be unpacked wholesale onto a workstation just because one bucket has to sign.
    # A multisig comes with its members -- it cannot be rebuilt without them -- and nothing else
    # comes along.
    if include:
        want = set(include)
        for e in entries:
            if e["name"] in want and e["kind"] == "multisig":
                want |= set(e["members"])
        entries = [e for e in entries if e["name"] in want]
        if not entries:
            sys.exit(f"--include matched nothing in {src}")
    restored, skipped, bad = 0, 0, []

    # members/singles FIRST -- a multisig cannot be rebuilt until its members are present.
    for e in [x for x in entries if x["kind"] == "single"]:
        ln = local_name(e["name"], strip)
        if qadenad("keys", "show", ln, "-a").returncode == 0:
            skipped += 1; continue
        tmp = Path(src).parent / f".{ln}.armor"
        tmp.write_text(e["armor"] + "\n")
        r = qadenad("keys", "import", ln, str(tmp), stdin=f"{pw}\n")
        tmp.unlink(missing_ok=True)
        if r.returncode != 0:
            bad.append((e["name"], r.stderr.strip()[:120])); continue
        restored += 1

    for e in [x for x in entries if x["kind"] == "multisig"]:
        if qadenad("keys", "show", local_name(e["name"], strip), "-a").returncode == 0:
            skipped += 1; continue
        r = qadenad("keys", "add", local_name(e["name"], strip), "--multisig",
                    ",".join(local_name(m, strip) for m in e["members"]),
                    "--multisig-threshold", str(e["threshold"]))
        if r.returncode != 0:
            bad.append((e["name"], r.stderr.strip()[:120])); continue
        restored += 1

    # VERIFY: every restored key must resolve to the address the vault recorded.  Without this
    # a wrong algo or member order restores silently and the genesis addresses go dead.
    mismatched = []
    for e in entries:
        got = qadenad("keys", "show", local_name(e["name"], strip), "-a").stdout.strip()
        if got != e["address"]:
            mismatched.append((e["name"], e["address"], got or "<absent>"))

    print(f"restored {restored}, already present {skipped}")
    for n, err in bad:
        print(f"  FAILED {n}: {err}", file=sys.stderr)
    if mismatched:
        print("\nADDRESS MISMATCH -- these do not match the vault:", file=sys.stderr)
        for n, want, got in mismatched:
            print(f"  {n}\n    vault: {want}\n    got:   {got}", file=sys.stderr)
        return 1
    if bad:
        return 1
    print(f"all {len(entries)} address(es) verified against the vault")
    return 0


def cmd_verify(src):
    vault = json.loads(Path(src).read_text())
    ok, missing = 0, []
    for e in vault["keys"]:
        got = qadenad("keys", "show", e["name"], "-a").stdout.strip()
        if got == e["address"]:
            ok += 1
        else:
            missing.append((e["name"], e["address"], got or "<absent>"))
    print(f"{ok}/{len(vault['keys'])} key(s) present and matching")
    for n, want, got in missing:
        print(f"  {n}: vault {want}, keyring {got}")
    return 1 if missing else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("export", help="write the keyring's dev keys to a vault file")
    e.add_argument("--out", required=True, metavar="FILE")
    e.add_argument("--passphrase-file", required=True, metavar="FILE")
    e.add_argument("--prefix", default="dev-")
    e.add_argument("--include", help="comma-separated key names to export (members implied)")
    e.add_argument("--exclude", help="comma-separated key names to omit (members implied)")
    i = sub.add_parser("import", help="restore a vault into the keyring (after init.sh)")
    i.add_argument("--in", dest="src", required=True, metavar="FILE")
    i.add_argument("--passphrase-file", required=True, metavar="FILE")
    i.add_argument("--include", help="comma-separated key names to restore (members implied); "
                                     "omit to restore the whole vault")
    i.add_argument("--strip-prefix", metavar="PREFIX",
                   help="restore dev-X as X, so ignite finds the key under the account name")
    v = sub.add_parser("verify", help="check the keyring matches a vault, without importing")
    v.add_argument("--in", dest="src", required=True, metavar="FILE")
    a = ap.parse_args()
    if a.cmd == "export": return cmd_export(a.out, a.passphrase_file, a.prefix,
                                            (a.include or "").split(",") if a.include else None,
                                            (a.exclude or "").split(",") if a.exclude else None)
    if a.cmd == "import": return cmd_import(a.src, a.passphrase_file, a.strip_prefix,
                                            (a.include or "").split(",") if a.include else None)
    if a.cmd == "verify": return cmd_verify(a.src)


if __name__ == "__main__":
    sys.exit(main() or 0)
