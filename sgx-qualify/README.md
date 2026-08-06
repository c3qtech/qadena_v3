# sgx-qualify — pre-qualify an SGX installation

A minimal, self-contained EGo remote attestation test. **No Qadena code.** Its job is to answer one
question before you trust a machine with anything real:

> Can this box produce a DCAP quote that another box can independently verify?

That is the property every other guarantee rests on, and it is the one most likely to be broken by
the environment rather than by software — a missing quote provider, an unconfigured PCCS, a user
outside the `sgx_prv` group, an out-of-date TCB. All of those look fine until an attestation is
actually attempted between two machines.

## Why two machines

A single box verifying its own quote proves much less than it appears to. Quote *generation* needs
`/dev/sgx_provision` and a working quote provider; quote *verification* needs collateral (TCB info,
QE identity, CRLs) fetched from a PCCS or Intel. On one machine those can be satisfied by the same
cached state, so a self-test can pass while a genuine remote verifier fails.

Splitting the roles is the point:

- **server** runs *inside* an enclave, binds its TLS certificate into a quote, and serves both.
- **client** runs *outside* any enclave, on a different machine, and verifies the quote from scratch.

## What it proves, step by step

1. **The enclave can generate a quote.** `enclave.GetRemoteReport` succeeds — so the driver, the
   provisioning device and the quote provider all work on the server.
2. **A remote party can verify it.** `eclient.VerifyRemoteReport` succeeds on the client — so the
   verification libraries and collateral work there, independently.
3. **The quote is bound to the TLS key.** The report's user data is `sha256(server certificate)`.
   Without this the quote proves an enclave exists somewhere, not that *this* connection reaches it.
   Relaying someone else's valid quote is the attack this closes.
4. **The measurements are what you expect.** MRENCLAVE, MRSIGNER, product id and security version are
   printed, and can be asserted with flags.
5. **The channel actually terminates in the enclave.** The client then makes a TLS request pinned to
   the attested certificate. PKI is deliberately not involved: trust comes from the quote.

## Two variants

Both do the same verification; they differ only in how the quote travels.

| | use when |
|---|---|
| `net/` — server + client | the machines can reach each other over IP |
| `offline/` — attest + verify | they cannot; you copy/paste a text blob |

Build once on the machine that will run the enclave. It builds both:

    ./build.sh

The enclave binaries are built with `ego-go` and signed; the verifier binaries with plain `go`,
because they run outside any enclave. `build.sh` prints the measurements — record them, since
pinning `--unique-id` and `--signer-id` is what turns an inspection into a gate.

### Networked

    # machine A (the enclave)
    ego run ./net/server/server

    # machine B — copy the client binary over; it needs no enclave
    ./net/client/client --host <machine-A-ip>

### Offline (copy/paste)

Three copies, because freshness needs a challenge:

    # machine B (verifier) — issue a nonce
    ./offline/verify/verify --new-nonce

    # machine A (enclave) — bind that nonce into a quote
    ego run ./offline/attest/attest --nonce <nonce> > quote.txt

    # machine B — paste it back
    ./offline/verify/verify --nonce <nonce> --quote-file quote.txt

**The nonce is not ceremony.** A quote carries no timestamp, so one copied without a challenge shows
only that the machine could produce a valid quote at *some* point — possibly before it was
downgraded, or after it was decommissioned. `verify` refuses to run without one unless you pass
`--allow-stale`, which is reasonable when you are qualifying hardware and freshness genuinely does
not matter.

### Asserting rather than inspecting

    ./net/client/client --host <ip> \
        --unique-id <MRENCLAVE> --signer-id <MRSIGNER> --require-production

`--require-production` fails if the enclave was signed with `"debug": true`. Worth having: a debug
enclave produces a perfectly valid quote, and its memory is not confidential. `enclave-*.json` here
set `"debug": false`, so a real platform is exercised by default.

## Interpreting failures

- `GetRemoteReport` fails on the server → the quote provider or `/dev/sgx_provision` is the problem.
  Check membership of `sgx_prv` (a *different* group from `sgx`) and that
  `libsgx-dcap-default-qpl` is installed.
- `VerifyRemoteReport` fails on the client → verification collateral is the problem, usually
  `/etc/sgx_default_qcnl.conf` pointing at an unreachable PCCS.
- Verification succeeds but reports a TCB status other than `UpToDate` → the platform needs microcode
  or PSW updates. This is a real finding: it is exactly what a remote relying party would reject.
- The certificate hash does not match → something is relaying another enclave's quote.
