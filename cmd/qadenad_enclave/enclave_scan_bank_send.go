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
// so a bank send that crosses a threshold is REFUSED.  On the transfer path an opted-in user may
// proceed and have a report filed instead; here the only available answer is no.

import (
	"context"

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

	// BOTH sides must be credentialed wallets.
	//
	// The sender, because the reporting threshold is chosen from residency and citizenship -- with
	// no jurisdiction there is no limit to hold them to, and allowing the send under a default would
	// make "hold no credential" the cheapest way to pick your own threshold.
	//
	// The recipient, because createSuspiciousTransaction decodes the destination credential too and
	// gives up if it is missing.  A send that could never be reported must not be one that only
	// needs reporting after it has settled.
	senderCountries, err := s.senderJurisdictions(msg.SrcWalletID)
	if err != nil {
		c.LoggerError(logger, "ScanBankSend couldn't resolve sender jurisdictions "+err.Error())
		return nil, err
	}

	if len(senderCountries) == 0 && !policy.AllowTransferWithoutEKYC {
		c.LoggerError(logger, "refusing bank send from "+msg.SrcWalletID+": no residency or citizenship on record")
		return nil, types.ErrNoEKYCForTransfer
	}

	if !policy.AllowTransferWithoutEKYC && !s.hasPersonalInfoCredential(msg.DstWalletID) {
		c.LoggerError(logger, "refusing bank send to "+msg.DstWalletID+": recipient is not a wallet with eKYC data")
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

	threshold := sdk.NewCoin(types.AttoUSDFiatDenom, c.SelectThreshold(senderCountries, msg.CountryThresholds, defaultThreshold))

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
		})
	}

	c.LoggerDebug(logger, "bank send "+msg.SrcWalletID+" -> "+msg.DstWalletID+" "+total.String()+
		" threshold "+threshold.String())

	// A single send at or above the limit.  Checked before anything is recorded, so a refused send
	// does not enter the window.
	if total.IsGTE(threshold) {
		c.LoggerError(logger, "refusing bank send: value "+total.String()+" >= threshold "+threshold.String())
		return nil, types.ErrGenericScan
	}

	// The rolling window, shared with transfer-funds: both paths key on the sender's wallet, so a
	// user cannot stay under a threshold by splitting activity between them.
	history := s.getScanTransferHistory(msg.SrcWalletID)
	cutoff := msg.Timestamp.Add(-policy.Window).Unix()
	history.Transfers = c.PruneExpired(history.Transfers, cutoff)
	history.Transfers = append(history.Transfers, entries...)

	for dstWalletID, v := range c.AggregateByDestination(history.Transfers) {
		if v.IsGTE(threshold) {
			c.LoggerError(logger, "refusing bank send: aggregate to "+dstWalletID+" is "+v.String()+
				" >= threshold "+threshold.String())
			// Returning without writing leaves the window untouched; the rolled-back transaction
			// would discard the write in any case.
			return nil, types.ErrGenericScan
		}
	}

	s.setScanTransferHistory(msg.SrcWalletID, history)

	return &types.ScanBankSendReply{Status: true}, nil
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
