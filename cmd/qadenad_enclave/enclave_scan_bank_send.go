package main

// The AML scan for a direct bank send.
//
// This is ScanTransaction's sibling.  It exists separately because almost nothing of that function
// applies here: a transfer's value is spread across Pedersen commitments and encrypted VShares that
// the enclave has to unpack, whereas a bank send's amount is public and the keeper has already
// priced it.  What the two genuinely share -- the jurisdiction lookup, the threshold choice, the
// rolling window -- is shared as code below, not by forcing one message to describe both shapes.
//
// The decisive difference in behaviour: MsgSend has no --opt-in-reason and no field to put one in,
// so a bank send that crosses a threshold reaches the report with an empty reason and gets the
// default one.  It is REPORTED and allowed, not refused -- unless the chain has set
// block_transfer_without_opt_in_reason, which chooses refusal over reporting on both paths.

import (
	"context"
	"errors"

	"cosmossdk.io/math"
	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

func (s *qadenaServer) ScanBankSend(ctx context.Context, msg *types.MsgScanBankSend) (*types.ScanBankSendReply, error) {
	if s.RealEnclave {
		c.LoggerDebug(logger, "ScanBankSend")
	} else {
		c.LoggerDebug(logger, "ScanBankSend "+c.PrettyPrint(msg))
	}

	policy := c.SuspiciousPolicyFromParams(msg.Params)

	// Each side must be either a credentialed wallet or a party on the scanned-contract whitelist.
	//
	// A wallet, because the reporting threshold is chosen from residency and citizenship -- with no
	// jurisdiction there is no limit to hold them to, and allowing the send under a default would
	// make "hold no credential" the cheapest way to pick your own threshold.
	//
	// A whitelisted party, because it has been approved by governance to move funds without one, and
	// can now be named in a report by address rather than by identity.  It is NOT exempt from the
	// scan: the value is still measured, still accumulates in the window, and is still reported when
	// it crosses.  What it escapes is only the requirement to be a person.
	//
	// The keeper resolved this membership and re-verified the pinned code ID before calling; the
	// enclave holds no wasm state and could not check it here.
	thresholdCountries, err := s.bankSendJurisdictions(msg)
	if err != nil {
		return nil, err
	}

	if msg.SrcContract == nil && len(thresholdCountries) == 0 && !policy.AllowTransferWithoutEKYC {
		c.LoggerError(logger, "refusing bank send from "+msg.SrcWalletID+": no residency or citizenship on record")
		return nil, types.ErrNoEKYCForTransfer
	}

	// ONBOARDING.  A send from a whitelisted party may go to an address with no identity at all --
	// that is exactly what a treasury does when it funds a fresh key, which then acquires a wallet
	// and a credential afterwards.  The value is still measured against the chain default threshold
	// and still reported if it crosses; the report names the recipient by address.
	//
	// Scoped to a whitelisted SENDER on purpose.  Every such sender is governance-approved and its
	// stated purpose is onboarding.  Between two ordinary parties the recipient must still be
	// identifiable, so this does not reopen the gap for user-to-user sends.
	allowUnidentifiedDst := msg.SrcContract != nil

	if msg.DstContract == nil && !allowUnidentifiedDst && !policy.AllowTransferWithoutEKYC &&
		!s.hasPersonalInfoCredential(msg.DstWalletID) {
		c.LoggerError(logger, "refusing bank send to "+msg.DstWalletID+": recipient is neither a wallet with eKYC data nor on the scanned-contract whitelist")
		return nil, types.ErrBankSendNotScannable
	}

	defaultThreshold, ok := math.NewIntFromString(msg.DefaultThresholdAttoUSD)
	if !ok || defaultThreshold.IsNil() || !defaultThreshold.IsPositive() {
		// the keeper prices this through the pricefeed and fails closed if it cannot, so an
		// unusable value means the two sides disagree about the message -- not something to guess
		// at, since every guess is either "report everything" or "report nothing"
		c.LoggerError(logger, "ScanBankSend unusable default threshold from keeper: "+msg.DefaultThresholdAttoUSD)
		return nil, types.ErrGenericScan
	}

	threshold := sdk.NewCoin(types.AttoUSDFiatDenom, c.SelectThreshold(thresholdCountries, msg.CountryThresholds, defaultThreshold))

	// One send can carry several denominations; the rule applies to their combined value, not to
	// each in turn, or splitting across denominations inside one message would evade it.
	total := sdk.NewCoin(types.AttoUSDFiatDenom, math.NewInt(0))
	entries := make([]*types.EncryptableScanTransfer, 0, len(msg.Coins))

	for _, coin := range msg.Coins {
		usdAmount, ok := math.NewIntFromString(coin.UsdAmountAttoUSD)
		if !ok || usdAmount.IsNil() || usdAmount.IsNegative() {
			c.LoggerError(logger, "ScanBankSend unusable usd amount for "+coin.Denom+": "+coin.UsdAmountAttoUSD)
			return nil, types.ErrGenericScan
		}
		amount, ok := math.NewIntFromString(coin.Amount)
		if !ok || amount.IsNil() || amount.IsNegative() {
			c.LoggerError(logger, "ScanBankSend unusable amount for "+coin.Denom+": "+coin.Amount)
			return nil, types.ErrGenericScan
		}

		usdCoin := sdk.NewCoin(types.AttoUSDFiatDenom, usdAmount)
		total = total.Add(usdCoin)

		entries = append(entries, &types.EncryptableScanTransfer{
			UnixTime:            msg.Timestamp.Unix(),
			DestinationWalletID: msg.DstWalletID,
			USDCoinAmount:       usdCoin,
			CoinAmount:          sdk.NewCoin(coin.Denom, amount),
			// carried so a later aggregate report can describe this destination correctly, even
			// when the send that triggers it went somewhere else entirely
			DestinationContract: msg.DstContract,
		})
	}

	c.LoggerDebug(logger, "bank send "+msg.SrcWalletID+" -> "+msg.DstWalletID+" "+total.String()+
		" threshold "+threshold.String())

	// A single send at or above the limit.
	//
	// MsgSend has no --opt-in-reason and nowhere to put one, so every reportable bank send reaches
	// here with an empty reason.  Before the reason became optional that meant this path could only
	// ever REFUSE; now it files a report with the default reason and lets the send through, unless
	// the chain has asked for refusal.
	if total.IsGTE(threshold) {
		if policy.BlockTransferWithoutOptInReason {
			c.LoggerError(logger, "refusing bank send: value "+total.String()+" >= threshold "+threshold.String())
			return nil, types.ErrGenericScan
		}
		c.LoggerDebug(logger, "reporting bank send: value "+total.String()+" >= threshold "+threshold.String())
		reported := c.TransferFunds{
			Time:                msg.Timestamp,
			SourceWalletID:      msg.SrcWalletID,
			DestinationWalletID: msg.DstWalletID,
			USDCoinAmount:       total,
			CoinAmount:          firstCoinAmount(entries),
		}
		if err := s.createSuspiciousTransaction(ctx, "Bank send value >= reporting threshold",
			s.getSharedEnclaveParamsJarID(), reported, c.DefaultOptInReason,
			msg.SrcContract, msg.DstContract, allowUnidentifiedDst); err != nil {
			// Refuse rather than settle unreported.  This is the case the whitelist used to hide:
			// a treasury send that crossed the threshold was simply never scanned, so there was
			// nothing to fail.  Now it is scanned, and a report that cannot be built stops it.
			return nil, err
		}
		// Not recorded, for the same reason ScanTransaction does not record a reported single
		// transfer: its whole value is now in a report, so leaving it in the window would let the
		// aggregate rule report the same money twice.
		return &types.ScanBankSendReply{Status: true}, nil
	}

	// The rolling window, shared with transfer-funds: both paths key on the sender's wallet, so a
	// user cannot stay under a threshold by splitting activity between them.
	history := s.getScanTransferHistory(msg.SrcWalletID)
	cutoff := msg.Timestamp.Add(-policy.Window).Unix()
	history.Transfers = c.PruneExpired(history.Transfers, cutoff)
	history.Transfers = append(history.Transfers, entries...)

	// Ordered by destination -- same consensus reason as ScanTransaction, and this is the path where
	// two destinations crossing at once is most reachable: the threshold comes from the CURRENT
	// recipient's jurisdiction, so a window accumulated under a loose limit is re-judged against a
	// tighter one as soon as the sender pays into a stricter jurisdiction.
	for _, agg := range c.AggregateByDestination(history.Transfers) {
		dstWalletID := agg.DestinationWalletID
		v := agg.USDCoinAmount
		if v.IsGTE(threshold) {
			if policy.BlockTransferWithoutOptInReason {
				c.LoggerError(logger, "refusing bank send: aggregate to "+dstWalletID+" is "+v.String()+
					" >= threshold "+threshold.String())
				// Returning without writing leaves the window untouched; the rolled-back
				// transaction would discard the write in any case.
				return nil, types.ErrGenericScan
			}
			c.LoggerDebug(logger, "reporting bank send aggregate to "+dstWalletID+" is "+v.String()+
				" >= threshold "+threshold.String())

			aggregated := c.TransferFunds{
				Time:                msg.Timestamp,
				SourceWalletID:      msg.SrcWalletID,
				DestinationWalletID: dstWalletID,
				USDCoinAmount:       v,
				CoinAmount:          firstCoinAmount(entries),
			}
			// The destination being reported is whichever one crossed, not necessarily the one this
			// send went to, so its descriptor comes from the window rather than from msg.
			if err := s.createSuspiciousTransaction(ctx, "Total bank send value >= reporting threshold",
				s.getSharedEnclaveParamsJarID(), aggregated, c.DefaultOptInReason,
				msg.SrcContract, destinationContract(history.Transfers, dstWalletID), allowUnidentifiedDst); err != nil {
				// Filed before the window is reset, so a failure leaves the accumulated history
				// intact rather than discarding it alongside a refused send.
				return nil, err
			}

			// Reported, so the pair starts over, exactly as on the transfer-funds path.
			history.Transfers = c.DropDestination(history.Transfers, dstWalletID)
		}
	}

	s.setScanTransferHistory(msg.SrcWalletID, history)

	return &types.ScanBankSendReply{Status: true}, nil
}

// firstCoinAmount picks the token amount to name in a report.
//
// A report carries ONE token amount beside the USD total, but a bank send may carry several
// denominations and there is no meaningful sum across them -- the same reason ScanTransaction names
// only the current transfer's coin when it reports an aggregate.  The USD figure is the one that
// matters for the threshold; this is context.  Coins arrive in the order the sender listed them.
func firstCoinAmount(entries []*types.EncryptableScanTransfer) sdk.Coin {
	if len(entries) == 0 {
		return sdk.NewCoin(types.AttoUSDFiatDenom, math.NewInt(0))
	}
	return entries[0].CoinAmount
}

// destinationContract recovers how a destination in the window should be described in a report.
//
// Returns nil for a wallet, which is both the common case and the right answer for any entry
// written by the transfer-funds path -- that path only ever moves value between wallets, so its
// entries carry no descriptor.
//
// The first match wins.  Entries for one destination can in principle disagree, if the address was
// whitelisted or de-whitelisted part way through the window; the newest entry is not obviously more
// correct than the oldest, and either way the report names an address that is right in both.
func destinationContract(transfers []*types.EncryptableScanTransfer, dstWalletID string) *types.ScannedContractWhitelist {
	for _, t := range transfers {
		if t.DestinationWalletID == dstWalletID && t.DestinationContract != nil {
			return t.DestinationContract
		}
	}
	return nil
}

// bankSendJurisdictions picks whose jurisdictions set the reporting threshold for this send.
//
// Normally the SENDER's, as on the transfer-funds path: the limit follows the person moving the
// money.  A whitelisted contract or treasury has neither residency nor citizenship, so when the
// sender is one, the RECIPIENT's jurisdictions are used instead, falling back to the chain default
// when they have none either.
//
// Recipient rather than default-always because a regulator's interest in an escrow paying out is the
// person being paid -- a beneficiary in a jurisdiction with a low limit should not get a higher one
// merely because the money arrived via a contract.  It cannot be gamed the way a sender-chosen
// jurisdiction could: the recipient does not decide who pays them, and SelectThreshold takes the
// most restrictive of whatever countries it is given.
func (s *qadenaServer) bankSendJurisdictions(msg *types.MsgScanBankSend) ([]string, error) {
	if msg.SrcContract != nil {
		if msg.DstContract != nil {
			// Party to party: neither has a jurisdiction, so the chain default applies.
			return nil, nil
		}

		// Falling back to the recipient.  A MISSING recipient wallet is not an error on this path:
		// a whitelisted sender's whole purpose is onboarding, so the recipient very often has no
		// wallet yet -- that is every treasury funding send on a fresh chain.  It simply means no
		// jurisdiction is available, and the chain default applies.
		countries, err := s.senderJurisdictions(msg.DstWalletID)
		if err != nil {
			if errors.Is(err, types.ErrWalletNotExists) {
				c.LoggerDebug(logger, "recipient "+msg.DstWalletID+
					" has no wallet; using the chain default threshold")
				return nil, nil
			}
			c.LoggerError(logger, "ScanBankSend couldn't resolve recipient jurisdictions "+err.Error())
			return nil, err
		}
		return countries, nil
	}

	countries, err := s.senderJurisdictions(msg.SrcWalletID)
	if err != nil {
		// A sender that is not a qadena wallet at all -- a plain key, an unlisted contract, an EVM
		// account -- reports "wallet does not exist", which is true but explains nothing here.  The
		// reason the send is refused is that it cannot be scanned, so say that instead.  Unlike the
		// recipient above, there is no default to fall back to: letting an unidentifiable SENDER
		// through under the chain default would make "hold no credential" the cheapest way to pick
		// your own threshold.
		if errors.Is(err, types.ErrWalletNotExists) {
			c.LoggerError(logger, "refusing bank send: sender "+msg.SrcWalletID+
				" is not a wallet and is not on the scanned-contract whitelist, cannot be scanned")
			return nil, types.ErrBankSendNotScannable
		}
		c.LoggerError(logger, "ScanBankSend couldn't resolve sender jurisdictions "+err.Error())
		return nil, err
	}

	return countries, nil
}

// hasPersonalInfoCredential reports whether an address is a wallet carrying a personal-info
// credential.  Deliberately not senderJurisdictions: that decrypts the credential to read countries,
// which is unnecessary work when the only question is whether a report could name this party.
func (s *qadenaServer) hasPersonalInfoCredential(walletID string) bool {
	wallet, found := s.getWallet(walletID)
	if !found || wallet.CredentialID == "" {
		return false
	}

	_, found = s.getCredential(wallet.CredentialID, types.PersonalInfoCredentialType)
	return found
}
