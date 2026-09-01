#!/usr/bin/env python3
"""Monthly unlock and circulating-supply schedule, TGE to month 120.

    ./export_unlock_schedule.py                 # writes unlock_schedule.csv
    ./export_unlock_schedule.py --summary       # and prints the milestones

INTEGER ARITHMETIC ONLY (HARD RULE 3).  Amounts are carried in aqdn as Python ints.
Percentages are applied as `amount * pct // 100`, never as a float multiply, so the
columns sum exactly and the last period absorbs the rounding remainder rather than
scattering it.

THE ASSUMPTIONS, STATED RATHER THAN BURIED
------------------------------------------
1. EVERY GRANT IS ISSUED AT TGE.  The brief says to model it this way and to label it.
   It is deliberately pessimistic for unlock timing: real grants are issued later, so
   real unlocks are LATER than this file shows, never earlier.  For founders and backers
   the assumption is close to true -- their start_time is backdated to TGE -- and for
   personnel and partners it is not, because their start_time is the grant date.

2. THE BUCKET'S TERMS ARE THE GRANT'S TERMS.  cliff_days / vest_months /
   cliff_release_pct describe what grants OUT of a bucket must carry; there is no
   vesting on the bucket itself (nothing is locked at genesis).  Applying them to the
   whole bucket is what makes a schedule possible at all.

3. 30-DAY MONTHS.  A period is 2,592,000 seconds, matching the vesting periods the
   runbooks issue.  Twelve of them is 360 days, so this drifts ~5 days per year against
   the calendar.  Month 120 is therefore ~118 calendar months, not exactly ten years.

4. CIRCULATING IS DRIVEN BY THE `circulating` COLUMN, not by unlocking:
       no       never counts, however much has unlocked -- escrow that has not been paid out
       yes      all unlocked amounts count
       partial  only the cliff_release portion counts (Foundation: the 56M liquid tranche;
                the 504M is delegated foundation principal, not float)
   "Unlocked" and "circulating" are different questions and this file answers both.

   KNOWN LIMITATION, AND IT IS NOT A BUG IN THIS SCRIPT.  Implemented exactly as the
   brief specifies, the circulating curve is FLAT at 56,010,100 QDN for all 120 months:
   85% of supply sits in buckets marked `circulating=no`, and nothing in the CSV ever
   moves a token out of that state.  The column describes a bucket's status AT GENESIS,
   not the destiny of the grants issued from it -- a founder grant that vests and is sold
   is plainly circulating, but its bucket is still `no`.

   So the `circulating_qdn` column answers "how much is liquid in accounts that are
   themselves float" and NOT "how much could reach a market". The second question needs
   a payout assumption per bucket that the CSV does not carry. Reported, not invented
   (HARD RULE 1); see the README.

6. INFLATION COMPOUNDS MONTHLY at 1%/12, as `supply // 1200` per month.  x/mint pays per
   block against total supply; monthly is the coarsest step that still compounds, and
   integer division makes it reproducible.  Provisions go to BONDED STAKE, so they are
   NOT added to circulating here -- staking rewards are liquid, but who receives them
   depends on the delegation programme, which is not in this file.
"""

import argparse, csv, sys
from pathlib import Path

AQDN = 10**18
TOTAL_QDN = 4_000_000_000
MONTHS = 120
DAYS_PER_MONTH = 30


def load(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    for r in rows:
        r["_aqdn"] = int(r["tokens_qdn"]) * AQDN
        r["_cliff_m"] = int(r["cliff_days"]) // DAYS_PER_MONTH
        r["_vest_m"] = int(r["vest_months"])
        r["_cliff_pct"] = int(r["cliff_release_pct"])
    return rows


def unlocked_at(r, month):
    """aqdn unlocked from this row by the END of `month` (month 0 == TGE).

    Shape: nothing until the cliff; cliff_release_pct at the cliff; the remainder
    linear over vest_months; the final period absorbs the rounding remainder so the
    series ends exactly at the row total.
    """
    total = r["_aqdn"]
    if r["_vest_m"] == 0 and r["_cliff_m"] == 0:
        return total                                   # no terms: liquid from TGE
    if month < r["_cliff_m"]:
        return 0
    cliff_amt = total * r["_cliff_pct"] // 100
    if r["_vest_m"] == 0:
        return total
    elapsed = month - r["_cliff_m"]
    if elapsed >= r["_vest_m"]:
        return total                                   # exact, absorbs any remainder
    linear_total = total - cliff_amt
    return cliff_amt + linear_total * elapsed // r["_vest_m"]


def circulating_at(r, month):
    mode = r["circulating"].strip().lower()
    if mode == "no":
        return 0
    if mode == "yes":
        return unlocked_at(r, month)
    if mode == "partial":
        # only the liquid tranche; the rest is foundation principal, not float
        if month < r["_cliff_m"]:
            return 0
        return r["_aqdn"] * r["_cliff_pct"] // 100
    sys.exit(f"export_unlock_schedule: bucket {r['bucket_id']}: unknown circulating "
             f"value {r['circulating']!r} (expected no/yes/partial)")


def build(rows):
    """Yield one dict per month."""
    supply = TOTAL_QDN * AQDN
    for m in range(MONTHS + 1):
        if m > 0:
            supply += supply // 1200               # 1%/yr compounded monthly, integer
        rec = {"month": m}
        unlocked_total = 0
        circ_total = 0
        for r in rows:
            key = f"{r['bucket_id']}_{r['bucket_name'].replace(' ', '_')}"
            u = unlocked_at(r, m)
            rec[key] = u // AQDN
            unlocked_total += u
            circ_total += circulating_at(r, m)
        rec["unlocked_total_qdn"] = unlocked_total // AQDN
        rec["circulating_qdn"] = circ_total // AQDN
        rec["minted_supply_qdn"] = supply // AQDN
        # basis points against the MOVING total, not against 4e9 -- inflation dilutes
        rec["circulating_bps_of_supply"] = (circ_total * 10_000) // supply
        yield rec


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    here = Path(__file__).parent
    ap.add_argument("--csv", type=Path, default=here / "allocations.csv")
    ap.add_argument("--out", type=Path, default=here / "unlock_schedule.csv")
    ap.add_argument("--summary", action="store_true")
    args = ap.parse_args()

    rows = load(args.csv)
    recs = list(build(rows))

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(recs[0]), lineterminator="\n")
        w.writeheader()
        w.writerows(recs)
    print(f"wrote {args.out}  ({len(recs)} months, {len(recs[0])} columns)")

    tge = recs[0]
    # SANITY CHECK, REPORTED NOT CORRECTED.  The brief predicts ~56.0M + validator
    # floats at TGE, ~1.4%.  If this is far off, something upstream changed and the
    # right response is to say so -- not to adjust the model until it agrees.
    expect_low, expect_high = 55_000_000, 58_000_000
    got = tge["circulating_qdn"]
    verdict = "as predicted" if expect_low <= got <= expect_high else "!! OFF PREDICTION"
    print(f"TGE circulating: {got:,} QDN "
          f"({tge['circulating_bps_of_supply']/100:.2f}% of supply) -- {verdict}")
    if verdict.startswith("!!"):
        print(f"  brief predicts ~56.0M + validator floats (~1.4%). REPORTED, NOT ADJUSTED.")

    if args.summary:
        print(f"\n{'month':>5} {'unlocked':>16} {'circulating':>16} {'supply':>16} {'circ%':>7}")
        for m in (0, 6, 12, 18, 24, 36, 42, 60, 72, 84, 120):
            r = recs[m]
            print(f"{m:>5} {r['unlocked_total_qdn']:>16,} {r['circulating_qdn']:>16,} "
                  f"{r['minted_supply_qdn']:>16,} {r['circulating_bps_of_supply']/100:>6.2f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main())
