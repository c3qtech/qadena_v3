# Sponsoring a deployment — ekycph, ENF, and any programme after them

What the **foundation** does to bring up a sponsored, multisig-funded deployment that is *not*
SEC PH VERITAS.

The procedure is identical to [HOWTO-SPONSOR-VERITAS.md](HOWTO-SPONSOR-VERITAS.md) — same scripts,
same ceremonies, same checks — with one flag added. **Read that document for the reasoning**: why
there are two sponsor accounts, why the three authz authorities are exactly three, how much stake
expedited voting needs, what the ceremonies look like, and what it all costs. This page covers only
what differs.

> **This is not `testscripts/setup_ekycph.sh` or `setup_enf.sh`.** Those are test harnesses: they
> play both roles at once, hold every key in one keyring, and run against a devnet where `treasury`
> is a single key the primary holds. On a launch chain no such key exists. They now take
> `--fund-mode foundation-sponsored` so the *shape* matches, but the money still moves by a plain
> `tx bank send`, not by a ceremony.

---

## The one flag

Every foundation script takes `--deployment <name>`:

```
foundation_scripts/sec_veritas_before_step_1.sh --deployment ekycph --stage prepare ...
```

and each deployment has entry points that do exactly that and nothing else, so
`ls foundation_scripts/` reads as the sequence:

```
ekycph_before_step_1.sh      enf_before_step_1.sh
ekycph_after_step_1.sh       enf_after_step_1.sh
ekycph_after_step_2.sh       enf_after_step_2.sh
ekycph_after_step_3.sh       enf_after_step_3.sh
ekycph_verify.sh             enf_verify.sh
```

They are four-line wrappers. The implementation is the `sec_veritas_*` file in every case — there is
one copy of this logic, not three.

The SEC-side steps take the same flag:

```
veritas_scripts/step_1.sh --deployment ekycph --count 30 ...
veritas_scripts/step_2.sh --deployment ekycph
veritas_scripts/step_3.sh --deployment ekycph
```

**Steps 2 and 3 must be given the same `--deployment` as step 1.** They read the `variables.json`
step 1 wrote, and the flag is what decides which directory that is.

---

## What the flag actually selects

`foundation_scripts/deployment_profile.sh` maps one name to every namespace the deployment appears
in. `deployment_profile.sh --show ekycph` prints the lot.

| | veritas | ekycph | enf |
|---|---|---|---|
| appsvr sponsor | `foundation-veritas-appsvr` | `foundation-ekycph-appsvr` | `foundation-enf-appsvr` |
| users sponsor | `foundation-veritas-users` | `foundation-ekycph-users` | `foundation-enf-users` |
| admin key | `sec-veritas-admin` | `ekycph-admin` | `enf-admin` |
| create-wallet sponsor | `sec-create-wallet-sponsor` | `ekycph-create-wallet-sponsor` | `enf-create-wallet-sponsor` |
| identity provider | `secidentitysrvprv` | `ekycphidentitysrvprv` | `enfidentitysrvprv` |
| DSVS provider | `secdsvssrvprv` | `ekycphdsvssrvprv` | `enfdsvssrvprv` |
| DSVS signer | `secdsvs` | `ekycphdsvs` | `enfdsvs` |
| state directory | `~/sec-veritas` | `~/sec-ekycph` | `~/sec-enf` |
| sponsors record | `<coord>/veritas-sponsors.json` | `<coord>/ekycph-sponsors.json` | `<coord>/enf-sponsors.json` |
| pre-grant record | `<coord>/veritas-pregrant.json` | `<coord>/ekycph-pregrant.json` | `<coord>/enf-pregrant.json` |
| pool record | `<coord>/veritas-pool.json` | `<coord>/ekycph-pool.json` | `<coord>/enf-pool.json` |

### Why every one of these has to vary together

`sec_veritas_before_step_1.sh` said this before any second deployment existed:

> Bucket 10's notes list "SEC PH VERITAS 60M; future MOUs; OTC swap reserve" — so the foundation
> will sponsor more than one programme out of the same bucket, and a bare `foundation-appsvr` would
> collide the moment the second one starts. **The keyring has no namespaces: a name is unique per
> keyring and nothing warns on reuse.**

The collision is silent in both directions, which is what makes it worth a whole file:

- an `--appsvr` resolving to another programme's key **funds the wrong programme** out of the wrong
  allocation, and every transaction succeeds;
- a `veritas-pool.json` left over from an earlier run makes `*_verify.sh` **pass green against a
  pool that was never created** for this deployment.

Neither produces an error. So the mapping lives in one file and is selected by one flag, rather than
being a set of flags an operator has to remember to pass consistently across seven commands.

---

## Adding a deployment without editing any script

Write `~/launch/deployments/<name>.env` (override the directory with `$QADENA_DEPLOYMENT_DIR`):

```sh
DEPLOY_APPSVR="foundation-newprog-appsvr"
DEPLOY_USERS="foundation-newprog-users"
DEPLOY_ADMIN="newprog-admin"
DEPLOY_SPONSOR_BASE="newprog-create-wallet-sponsor"
DEPLOY_TREASURY="newprog-treasury"
DEPLOY_IDENTITY_PRV="newprogidentitysrvprv"
DEPLOY_DSVS_PRV="newprogdsvssrvprv"
DEPLOY_DSVS="newprogdsvs"
DEPLOY_SEC_HOME="$HOME/sec-newprog"
DEPLOY_FUND_BUCKET="pubsec"
```

The file is sourced **after** the built-in profile, so it can also correct one — pinning ekycph's
fund bucket, say, without touching the repo. The three record filenames are always derived from the
name and cannot be set here: if a profile could set them independently, two deployments could be
made to share one, which is the collision above.

An unknown name with no profile file is a hard error. It does **not** guess
`foundation-<name>-appsvr` — a typo'd deployment would otherwise create real keys and fund them.

---

## Which bucket pays

**ekycph and ENF come out of bucket 01, Adoption Programs** (`--fund-bucket adoption`, the profile
default). Bucket 10, Public Sector Programs, stays earmarked for SEC PH VERITAS and future MOUs —
its `allocations.csv` sub-allocation note names exactly that.

| deployment | bucket | slug | multisig |
|---|---|---|---|
| veritas | 10 Public Sector Programs | `pubsec` | **5 of 7** |
| ekycph | 01 Adoption Programs | `adoption` | **3 of 5** |
| enf | 01 Adoption Programs | `adoption` | **3 of 5** |

**The thresholds differ, and that changes the ceremony.** An adoption spend needs three signatures,
not five, and `--fund-members` names adoption's members:

```sh
foundation_scripts/ekycph_before_step_1.sh --stage prepare \
    --members     foundation-m1,foundation-m2,foundation-m3 \
    --fund-members adoption-m1,adoption-m2,adoption-m3
```

`--members` still names the **stake** bucket (03 Foundation Treasury) — that is unchanged, because
voting power comes from there for every deployment. `--fund-members` was called `--pubsec-members`
when pubsec was the only bucket that funded anything; the old name still works, but it is wrong for
two of the three profiles now.

Gas is sized per signature, so a run told the wrong member list fails at broadcast rather than
signing something unintended.

## The devnet harnesses

`testscripts/setup_ekycph.sh` and `setup_enf.sh` now take `--fund-mode`:

| | what happens |
|---|---|
| `foundation-sponsored` (default) | The foundation pays by fee grant. The deployment holds no tokens, gets its own admin key and its own `~/sec-<name>` state, and `<name>_after_step_3.sh` grants its sponsor pool. Mirrors the production flow. |
| `banksend` | The original: 2M qdn into `<name>-treasury` plus an AML whitelist exemption so a treasury can make direct bank sends at all. Kept for a deployment mid-migration. |

Two things about the sponsored path on a devnet:

- **It shares `foundation-appsvr` / `foundation-users` with `setup_veritas.sh`.** In production each
  programme gets its own pair; on the devnet there is one foundation, one keyring and one chain, and
  all three harnesses run against it in sequence. Sharing costs nothing — authz and feegrant are
  keyed on *(granter, grantee)*, so three deployments granting from one granter to three disjoint
  sets of grantees do not overwrite each other — and it avoids inventing two more mnemonics for a
  public repo. `testscripts/setup_foundation_accounts.sh` owns them: it recovers both from their
  fixed dev mnemonics and tops up the funding, idempotently, and every sponsored harness calls it.
  There is **no ordering requirement between the three deployments** — ekycph does not need VERITAS
  to have run.
- **`--deployment` is passed only in sponsored mode.** Sponsored mode is the only mode that creates
  an admin key, and without the flag step 1 would name it `sec-veritas-admin` — the same key
  `setup_veritas.sh` creates, in the same keyring, on the same devnet. `banksend` creates no admin
  key, so it cannot collide, and it keeps its previous invocation exactly, shared `~/sec-veritas`
  state directory included.

---

## Bringing a deployment up on a launch fleet

One command, the same shape as VERITAS's:

```sh
./testscripts/ekycph_full_setup.sh --site M1-M2   --rebuild-chain --count 30
./testscripts/enf_full_setup.sh    --site staging --from prepare
./testscripts/veritas_full_setup.sh --site M1-M2 --from prepare      # unchanged
```

All three are the same implementation, selected on two independent axes:

| axis | what it picks | values |
|---|---|---|
| `--site` | the machines, and therefore the chain: hosts, passphrase file, launch dir, advertised addresses, whether joiners bond | `M1-M2`, `staging` (Azure + AWS) |
| `--deployment` | the programme: sponsor keys, admin key, providers, allocation bucket, signing members | `veritas`, `ekycph`, `enf` |

They are independent because several deployments share one chain — that is the point of a launch
fleet. `veritas_full_setup_sec_staging.sh` is now a wrapper for `--site staging`; it used to be a
520-line copy, and it had already drifted (missing the `--keyring-passfile` argument and the
`compose.yml` check).

The ten stages are the ceremony sequence, and `--from` resumes at any of them:

```
bootstrap  prepare  step1  delegate  step2  approve  step3  pool  verify  app
           ^^^^^^^           ^^^^^^^          ^^^^^^^        ^^^^
           the foundation's four multisig actions, between SEC's three steps
```

**The ceremony differs by bucket, and that is why the profile carries the members.** ekycph and enf
fund from bucket 01, a **3-of-5** multisig; VERITAS funds from bucket 10, **5-of-7**. Passing
VERITAS's seven member names to an adoption ceremony would name keys that are in the keyring but
not in that bucket's multisig.

Add a site the same way you add a deployment — drop `<name>.env` into `~/launch/sites/` setting
`SITE_PRIMARY`, `SITE_JOINER` and the rest; see `testscripts/fleet_site_profile.sh`.

---

## Running the whole thing on a devnet

`testscripts/ekycph_devnet_setup.sh` and `enf_devnet_setup.sh` do the entire bring-up end to end,
in stages, against a local devnet.  **They are not the launch path** -- they fund by
`tx bank send --from treasury`, a key no launch chain has. They are the devnet counterpart of
`testscripts/veritas_full_setup.sh` (which targets a launch fleet and does every foundation spend as
a multisig ceremony); the stage names line up on purpose.

| stage | what it does |
|---|---|
| `build` | compile and re-init the chain. **Destructive** — refuses without `--allow-build` |
| `chain` | start the node, wait for blocks |
| `base` | stake the pioneer; create and fund the two foundation sponsor accounts |
| `setup` | the deployment: steps 1–3, the foundation's two actions, the sponsor pool |
| `verify` | the 15 gating checks |
| `app` | patch the app-server env file and restart the stack |

**To skip the build**, which is the usual case, start at a later stage:

```sh
./testscripts/ekycph_devnet_setup.sh --from setup            # node already running, run to the end
./testscripts/enf_devnet_setup.sh --from base --until verify # everything but the app-server
./testscripts/enf_devnet_setup.sh --from setup -- --no-contracts # pass-through after --
```

`--from` defaults to `build`, and the build stage **refuses to run without `--allow-build`** — it
re-inits the chain, destroying every wallet, credential and grant on it, including another
deployment's. A bare run therefore stops and tells you the two commands above rather than wiping the
chain.

Every stage is idempotent, so re-running a completed one is safe and cheap: a second run of a green
ekycph deployment skips both governance rounds and finishes in about a fifth of the output. On
failure the script names the stage it died in and prints the `--from` that resumes there.

### Measured on this Mac, 2026-09-09, chain `qadena_4828-1`

- ekycph from scratch: 15/15 checks, exit 0
- ENF from scratch: 15/15 — and it detected ekycph's provider already registered, so it did not
  re-run it
- ekycph re-run over its own green deployment: 15/15, through the `app` stage

---

## Verifying

Same 15 checks, same reasoning as [HOWTO-SPONSOR-VERITAS.md](HOWTO-SPONSOR-VERITAS.md#verifying-the-result):

```sh
foundation_scripts/ekycph_verify.sh --coord-home ~/launch/coord
```

`--coord-home` reads `ekycph-sponsors.json`, `ekycph-pregrant.json` and `ekycph-pool.json` from
that directory, so the foundation types no addresses. The credential and signatory checks follow the
profile too — they look for `ekycph-create-wallet-sponsor` and `ekycphdsvs`, not SEC's names, so a
green run on the wrong deployment's records is not possible.
