# Bringing up SGX machines

The short version of the two-node procedure, for REAL SGX rather than debug enclaves. Everything
here is the same as `HOWTO-TWO-NODE-STATE-SYNC.md` except where noted; the differences are what
this file is for.

## What has to be true first

- **x86_64 Ubuntu.** `ego` ships as an amd64-only `.deb` and the Intel SGX apt repo is gated on
  `arch=amd64` (`ubuntu/setup_qadena_build.sh:122`), so an ARM box cannot be an SGX node at all.
  It can still be a *debug* node — that is the path the rest of the docs describe.
- **`ubuntu/setup_qadena_build.sh` has been run**, as root. It installs ego, docker and the SGX
  DCAP quote provider, and — the part that is easy to miss — adds the login user to the groups
  owning `/dev/sgx_enclave` and `/dev/sgx_provision`, which are DIFFERENT groups (`sgx`, `sgx_prv`).
- **`/dev/sgx_enclave` exists.** If it does not, the machine has no usable SGX and everything below
  will silently produce a debug enclave instead.

## Build and package, on the SGX machine

    buildscripts/build.sh --build-sgx
    buildscripts/package_release.sh --out /tmp/pkg

`--build-sgx` is a reproducible docker build and takes roughly 24 minutes. It needs a CLEAN working
tree, because it runs `git clean -fd` first — uncommitted work will be deleted.

`package_release.sh` REFUSES to package an unsigned enclave from a machine that has ego, which is
the accidental-debug-package case: an unsigned binary here means the build did not do what you
thought. It records `qadenad_enclave.identity_mode: sgx` in the manifest, and `install.sh` on the
target then requires ego to read the measurement back.

**Build once, distribute.** The build is reproducible, so a binary built here is equivalent to one
built on the joiner — and installing the joiner from a package built on the primary makes the
measurements match BY CONSTRUCTION. Building the two nodes independently is where drift bites.

## Register the measurement, if it is new to the chain

    testscripts/test_update_enclave_identity.sh <uniqueID> <signerID> unvalidated

`package_release.sh` prints the exact command with the right ids. `EnclaveIdentity` is keyed by
measurement, so a joiner whose enclave differs by one byte is refused by `verifyRemoteReport` — and
the error names the measurement, not the cause.

## Install on the joiner

    tar xzf qadena-full-<version>-<commit>.tar.gz
    ./qadena-full-<version>-<commit>/install.sh

Run the install as the user who will own the node, **not** with `sudo`. It writes only into that
user's `~/qadena`; nothing in it needs root. A sudo install leaves the tree root-owned, and the
operator's own CLI then fails on its unreadable `config/client.toml`. Opening `/dev/sgx_*` is a
group membership question, which `setup_qadena_build.sh` already arranges.

Or let the bringup do it, which also stops the node first and verifies the measurement:

    ./testscripts/1st_node_bringup.sh --primary <primary> --joiner <joiner> --only 8

## Bring it up

    ./testscripts/nth_node_bringup.sh \
        --primary <primary-ip> --joiner <joiner-ip> \
        --pioneer <a-name-the-chain-has-never-seen> \
        --state-sync \
        --from 1 --until 5

`--until 5` stops after the node is up and caught up, before the validator conversion — which is
what you want for a node that is meant to follow. Drop it (or `--until 7`) to convert and then check
peer agreement. `--only N` runs a single phase.

For a THIRD node, add `--seed2 <an existing peer>`: state-sync only turns on when two
genesis-pioneer IPs agree on the trust height and hash, and with only two machines the primary has
to be both, which corroborates nothing. A real second peer makes that check mean something.

The pioneer name must be unused. The chain remembers names, so a re-join after wiping the joiner
needs a fresh one.

## What differs from the debug path

| | debug | SGX |
|---|---|---|
| identity | a go:embed'ed string, e.g. `unique047` | a 64-hex measurement from `ego uniqueid` |
| root | not needed — the node runs as the login user | **required**: the enclave opens `/dev/sgx_enclave` |
| `export-private-state` | works, including `--digest-only` | **refused** — see below |
| build | plain `build.sh` | `build.sh --build-sgx`, ~24 min, clean tree |

The harness detects this per host (`sudo_for()`) and uses sudo only where an SGX device is present,
so a mixed pair — SGX primary, debug joiner — works without changes.

**Inspecting enclave state on SGX.** `export-private-state` refuses on a real enclave, so the
digest that debug builds use to compare private state is not available. What IS available is

    qadenad enclave store-hash

which returns per-store hashes and never their contents. It covers the ten MIRRORED stores only;
the genuinely private tables — the PCXY index, the AML window — have no SGX-safe equivalent yet.
That gap is worth knowing about before you need it: the divergences found on this chain so far were
all in tables `store-hash` does not cover.

## Verifying the build is reproducible

    ./testscripts/regression.sh --with-sgx

Builds the enclave twice and requires both to measure identically. It FAILS rather than skips when
ego, docker or SGX are absent, which is deliberate — a reproducibility check that silently skips is
worse than none. Slow, and it needs a clean tree for the same reason as above.
