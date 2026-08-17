package keeper

import (
	//	"fmt"

	//  "errors"

	//	"math/big"

	//	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"bytes"
	"compress/gzip"

	//  "os"
	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"

	sdk "github.com/cosmos/cosmos-sdk/types"

	//  "github.com/tendermint/tendermint/crypto/tmhash"
	//  "encoding/json"

	//tmtypes "github.com/cometbft/cometbft/proto/tendermint/types"
	"cosmossdk.io/core/header"
	errorsmod "cosmossdk.io/errors"
	//	errorsmod "cosmossdk.io/errors"

	//sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"

	"cosmossdk.io/math"

	//	storetypes "cosmossdk.io/store/types"

	"encoding/hex"

	"context"
	"time"

	// for enclave access
	"cosmossdk.io/log"
	//	"github.com/cometbft/cometbft/libs/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	//  storetypes "github.com/cosmos/cosmos-sdk/store/types"
	// authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
)

func (k Keeper) ValidateCredential(sdkctx sdk.Context, msg *types.MsgBindCredential) (bool, error) {
	return k.EnclaveValidateCredential(sdkctx, msg)
}

// returns 0 = invalid, 1 = valid real wallet, 2 = valid ephemeral wallet
func (k Keeper) ValidateDestinationWallet(sdkctx sdk.Context, msg *types.MsgCreateWallet) (int, error) {
	return k.EnclaveValidateDestinationWallet(sdkctx, msg)
}

// this is called during "transfer" funds
func (k Keeper) ValidateTransferPrime(sdkctx sdk.Context, msg *types.MsgTransferFunds) (bool, error) {
	return k.EnclaveValidateTransferPrime(sdkctx, msg)
}

// this is called during "receive" funds
func (k Keeper) ValidateTransferDoublePrime(sdkctx sdk.Context, msg *types.MsgReceiveFunds) (bool, error) {
	return k.EnclaveValidateTransferDoublePrime(sdkctx, msg)
}

// usdRateFor returns the qdn->usd rate for one denomination, and FAILS CLOSED.
//
// Shared by both scan paths.  The rate decides a transfer's USD value, and that value is what the
// suspicious-transaction threshold is compared against.  Earlier code substituted zero when no
// price was available, which made every transfer evaluate as 0 USD -- so the threshold never fired
// and arbitrarily large transfers passed unscanned, with nothing logged to say the control had been
// switched off.  Refusing is correct: a missing price is temporary and self-correcting, and a
// transfer that cannot be measured must not settle.
func (k Keeper) usdRateFor(sdkctx sdk.Context, denom string) (math.LegacyDec, error) {
	marketPrefix := "cn"
	token := denom
	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	} else if strings.HasPrefix(token, "erc20/") {
		marketPrefix = "cw"
		meta, _ := k.bankKeeper.GetDenomMetaData(sdkctx, denom)
		token = meta.Symbol
	}

	marketID := marketPrefix + ":" + strings.ToLower(token) + ":usd"
	cp, err := k.pricefeedKeeper.GetCurrentPrice(sdkctx, marketID)
	if err != nil {
		c.ContextError(sdkctx, "no price for "+marketID+", refusing to scan: "+err.Error())
		return math.LegacyDec{}, errorsmod.Wrapf(types.ErrNoPriceForDenom,
			"cannot scan transfer: market %s: %s", marketID, err.Error())
	}
	if cp.Price.IsNil() || !cp.Price.IsPositive() {
		c.ContextError(sdkctx, "non-positive price for "+marketID+", refusing to scan")
		return math.LegacyDec{}, errorsmod.Wrapf(types.ErrNoPriceForDenom,
			"cannot scan transfer: market %s reported a non-positive price", marketID)
	}

	c.LoggerDebug(k.logger, "marketID: "+marketID+" cp: "+cp.String())
	return cp.Price, nil
}

func (k Keeper) ScanTransaction(sdkctx sdk.Context, msg *types.MsgTransferFunds) (bool, error) {
	basePrice, err := k.usdRateFor(sdkctx, msg.TokenDenom)
	if err != nil {
		return false, err
	}

	return k.EnclaveScanTransaction(sdkctx, msg, basePrice)
}

// ScanBankSend puts a direct bank send through the same AML scan as a transfer.
//
// Unlike the transfer path, the amount is public, so the keeper prices it here rather than handing
// the enclave a rate to multiply -- which is also what lets a multi-denomination send be valued
// correctly, each denomination against its own market and failing closed on any it cannot price.
func (k Keeper) ScanBankSend(sdkctx sdk.Context, fromAddr, toAddr sdk.AccAddress, amt sdk.Coins) error {
	// Skipped for the same reason EnclaveScanTransaction skips it: the enclave's window write is
	// committed by the PostHandler, which does not run in CheckTx, so scanning here would measure
	// transfers that never happen and reject on a window that was never persisted.
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ScanBankSend not called in checktx")
		return nil
	}

	params := k.GetParams(sdkctx)

	defaultThreshold, countryThresholds, err := k.SuspiciousThresholdTable(sdkctx, params)
	if err != nil {
		c.ContextError(sdkctx, "ScanBankSend: cannot resolve thresholds, refusing to scan: "+err.Error())
		return err
	}

	coins := make([]*types.ScanBankSendCoin, 0, len(amt))

	for _, coin := range amt {
		rate, err := k.usdRateFor(sdkctx, coin.Denom)
		if err != nil {
			return err
		}

		// the smallest unit of the token times (usd per token) lands in attoUSD, matching how the
		// enclave values a transfer
		usd := math.LegacyNewDecFromInt(coin.Amount).Mul(rate).RoundInt()

		coins = append(coins, &types.ScanBankSendCoin{
			Denom:            coin.Denom,
			Amount:           coin.Amount.String(),
			UsdAmountAttoUSD: usd.String(),
		})
	}

	// Resolve each side against the scanned-contract whitelist BEFORE consulting the enclave.  The
	// enclave holds no wasm state and cannot tell a contract from a plain account, so this is the
	// only place the pinned code ID can be re-checked -- and it has to be re-checked on every send,
	// not just at proposal time, or a migration would silently inherit the approval.
	srcContract, err := k.resolveScannedParty(sdkctx, fromAddr)
	if err != nil {
		return err
	}
	dstContract, err := k.resolveScannedParty(sdkctx, toAddr)
	if err != nil {
		return err
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ScanBankSend(grpcctx, &types.MsgScanBankSend{
		Timestamp:               currentBlockHeader.Time,
		Height:                  currentBlockHeader.Height,
		SrcWalletID:             fromAddr.String(),
		DstWalletID:             toAddr.String(),
		Coins:                   coins,
		Params:                  params,
		CountryThresholds:       countryThresholds,
		DefaultThresholdAttoUSD: defaultThreshold,
		JarID:                   "",
		SrcContract:             srcContract,
		DstContract:             dstContract,
	})
	if err != nil {
		c.ContextError(sdkctx, "error returned by ScanBankSend on enclave "+err.Error())
		return err
	}
	if !r.Status {
		return types.ErrGenericScan
	}

	return nil
}

/*
   --------------------
   ENCLAVE CLIENT FUNCS
   --------------------
*/

var EnclaveGRPCClient types.QadenaEnclaveClient

var currentBlockHeader header.Info

var validatorAddress string

var EnclaveDialEnclave func(logger log.Logger, addr string, signerID string, uniqueID string) (*grpc.ClientConn, error)
var EnclaveClientVerifyRemoteReport func(sdkctx sdk.Context, remoteReportBytes []byte, certifyData string) (bool, string, string)

func SetValidatorAddress(address string) {
	validatorAddress = address
}

var SupportsUnixDomainSockets = true
var DefaultPort = 50051

func (k Keeper) GetEnclaveRPCClient() types.QadenaEnclaveClient {
	return EnclaveGRPCClient
}

func (k Keeper) InitEnclave() bool {
	addr := c.EnclaveAddr

	if addr == "" {
		// set default to localhost
		addr = "localhost:" + strconv.Itoa(DefaultPort)
		c.LoggerDebug(k.logger, "No enclave address provided, using default", addr)
	}
	signerID := c.EnclaveSignerID
	uniqueID := c.EnclaveUniqueID

	if addr != "" {
		for i := 0; i < 5; i++ {

			var conn *grpc.ClientConn
			var err error

			if SupportsUnixDomainSockets {
				addr = fmt.Sprintf("unix:///tmp/qadena_%d.sock", DefaultPort)

				c.LoggerDebug(k.logger, "Will connect to QadenaDEnclave (unix domain socket)", addr, "signerID", signerID, "uniqueID", uniqueID)

				conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithTimeout(time.Duration(5)*time.Second))
			} else if EnclaveDialEnclave == nil {
				c.LoggerDebug(k.logger, "Will connect to QadenaDEnclave (not secure)", addr)
				conn, err = grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithTimeout(time.Duration(5)*time.Second))
			} else {
				c.LoggerDebug(k.logger, "Will connect to QadenaDEnclave (secure) "+addr+" signerID "+signerID+" uniqueID "+uniqueID)
				conn, err = EnclaveDialEnclave(k.logger, addr, signerID, uniqueID)
			}

			if err != nil {
				c.LoggerError(k.logger, "Unable to 'Dial' "+addr+" err "+err.Error())
				// fall through
			} else {
				c.LoggerDebug(k.logger, "'Dialed' QadenaDEnclave "+addr)

				// test with a simple "hello"
				greeterClient := types.NewGreeterClient(conn)

				ctx, cancel := enclaveQueryContext()
				defer cancel()

				r, err := greeterClient.SayHello(ctx, &types.HelloRequest{Name: "Pong"})
				if err != nil {
					c.LoggerError(k.logger, "Could not ping the enclave "+err.Error())
				} else {
					c.LoggerDebug(k.logger, "Greeting "+r.GetMessage())
					EnclaveGRPCClient = types.NewQadenaEnclaveClient(conn)
					// The dial succeeded and the enclave answered a ping, so liveness is
					// established -- from here the watchdog owns the question.  Started exactly
					// once: InitEnclave has a single caller (app wiring) and returns on success.
					startEnclaveWatchdog(k.logger, conn)
					return true
				}
			}
			time.Sleep(time.Second)
		}
		return false
	} else {
		c.LoggerError(k.logger, "No enclave address provided")
	}

	return false
}

func (k Keeper) ClientVerifyRemoteReport(sdkctx sdk.Context, remoteReportBytes []byte, certifyData string) bool {
	var signerID string
	var uniqueID string
	var success bool

	// gunzip report
	var buf bytes.Buffer
	reader, err := gzip.NewReader(bytes.NewReader(remoteReportBytes))
	if err != nil {
		c.LoggerError(sdkctx.Logger(), "ClientVerifyRemoteReport: error gunzipping remote report "+err.Error())
		return false
	}
	_, err = buf.ReadFrom(reader)
	if err != nil {
		c.LoggerError(sdkctx.Logger(), "ClientVerifyRemoteReport: error gunzipping remote report "+err.Error())
		return false
	}
	remoteReportBytes = buf.Bytes()

	if EnclaveClientVerifyRemoteReport == nil {
		success, uniqueID, signerID = c.DebugVerifyRemoteReport(sdkctx.Logger(), remoteReportBytes, certifyData)

		if !success {
			return false
		}
	} else {
		success, signerID, uniqueID = EnclaveClientVerifyRemoteReport(sdkctx, remoteReportBytes, certifyData)

		if !success {
			return false
		}
	}

	c.ContextDebug(sdkctx, "ClientVerifyRemoteReport: uniqueID: "+uniqueID+" signerID: "+signerID)
	enclaveIdentity, found := k.GetEnclaveIdentity(sdkctx, uniqueID)
	if !found {
		c.ContextError(sdkctx, "ClientVerifyRemoteReport: couldn't find enclave identity")
		return false
	}

	c.ContextDebug(sdkctx, "ClientVerifyRemoteReport: enclaveIdentity signerID: "+enclaveIdentity.SignerID+" status: "+enclaveIdentity.Status)
	return enclaveIdentity.SignerID == signerID && enclaveIdentity.Status == types.ActiveStatus

}

// this will check if the pubKID is valid for the serviceProviderID
func (k Keeper) AuthenticateServiceProvider(sdkctx sdk.Context, pubKID string, serviceProviderType string) error {
	c.ContextDebug(sdkctx, "AuthenticateServiceProvider pubKID: "+pubKID+" serviceProviderType: "+serviceProviderType)
	creatorIntervalPubKID, found := k.GetIntervalPublicKeyIDByPubKID(sdkctx, pubKID)

	if !found {
		c.ContextDebug(sdkctx, "couldn't find interval public key ID directly, will check via enclave")
		return k.EnclaveValidateAuthenticateServiceProvider(sdkctx, pubKID, serviceProviderType)
	}

	c.ContextDebug(sdkctx, "creatorIntervalPubKID: "+creatorIntervalPubKID.String())

	if creatorIntervalPubKID.GetServiceProviderType() != serviceProviderType {
		return types.ErrServiceProviderUnauthorized
	}

	return nil
}

func (k Keeper) EnclaveValidateAuthenticateServiceProvider(sdkctx sdk.Context, pubKID string, serviceProviderType string) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateAuthenticateServiceProvider not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateAuthenticateServiceProvider(ctx, &types.ValidateAuthenticateServiceProviderRequest{PubKID: pubKID, ServiceProviderType: serviceProviderType})
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateAuthenticateServiceProvider on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "ValidateAuthenticateServiceProvider returns "+strconv.FormatBool(r.GetStatus()))
	if !r.Status {
		return types.ErrServiceProviderUnauthorized
	}

	return nil
}

func (k Keeper) EnclaveValidateAuthorizedSigner(sdkctx sdk.Context, creator string, requestingSignatory *types.VShareSignatory, requiredSignatory []*types.VShareSignatory, completedSignatories []*types.VShareSignatory) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateAuthorizedSigner not called in checktx")
		return true, nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateAuthorizedSigner(ctx, &types.ValidateAuthorizedSignerRequest{Creator: creator, RequestingSignatory: requestingSignatory, RequiredSignatory: requiredSignatory, CompletedSignatory: completedSignatories})
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateAuthorizedSigner on enclave "+err.Error())
		return false, err
	}
	c.ContextDebug(sdkctx, "ValidateAuthorizedSigner returns "+strconv.FormatBool(r.GetStatus()))
	return r.Status, nil
}

func (k Keeper) EnclaveValidateAuthorizedSignatory(sdkctx sdk.Context, creator string, signatory *types.VShareSignatory, currentSignatory []*types.VShareSignatory) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateAuthorizedSignatory not called in checktx")
		return true, nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateAuthorizedSignatory(ctx, &types.ValidateAuthorizedSignatoryRequest{Creator: creator, Signatory: signatory, CurrentSignatory: currentSignatory})
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateAuthorizedSignatory on enclave "+err.Error())
		return false, err
	}
	c.ContextDebug(sdkctx, "ValidateAuthorizedSignatory returns "+strconv.FormatBool(r.GetStatus()))
	return r.Status, nil
}

func (k Keeper) EnclaveClientSetWallet(sdkctx sdk.Context, wallet types.Wallet) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetWallet not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetWallet(ctx, &wallet)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetWallet on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetWallet returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetEnclaveIdentity(sdkctx sdk.Context, ei types.EnclaveIdentity) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetEnclaveIdentity not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetEnclaveIdentity(ctx, &ei)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetEnclaveIdentity on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetEnclaveIdentity returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientUpdateEnclaveIdentity(sdkctx sdk.Context, ei types.PioneerUpdateEnclaveIdentity) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "UpdateEnclaveIdentity not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.UpdateEnclaveIdentity(ctx, &ei)
	if err != nil {
		c.ContextError(sdkctx, "error returned by UpdateEnclaveIdentity on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "UpdateEnclaveIdentity returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetProtectKey(sdkctx sdk.Context, pk types.ProtectKey) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetProtectKey not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetProtectKey(ctx, &pk)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetProtectKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetProtectKey returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetRecoverKey(sdkctx sdk.Context, pk types.RecoverKey) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetRecoverKey not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetRecoverKey(ctx, &pk)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetRecoverKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetRecoverKey returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

// EnclaveClientSeedCredential forwards a credential for the MIRROR REPLAY rather than a live issue.
//
// Used only by enclaveSynchronizeStores.  The live create path keeps EnclaveClientSetCredential:
// its walletID gate and its strict duplicate check are correct for a user-submitted credential and
// wrong for a bulk re-push of rows the chain has already accepted.  See enclave.proto's
// SeedCredential comment and docs/TESTING-BACKLOG.md items 39 and 43.
func (k Keeper) EnclaveClientSeedCredential(sdkctx sdk.Context, credential types.Credential) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SeedCredential not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SeedCredential(ctx, &credential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SeedCredential on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SeedCredential returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetCredential(sdkctx sdk.Context, credential types.Credential) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetCredential not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetCredential(ctx, &credential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetCredential on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetCredential returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

// EnclaveClientRemoveCredential forwards a removal.  requesterWalletID is empty for the identity
// provider path, which may only remove ownerless credentials, and set to the owner's walletID when
// a user removes a credential of their own.
func (k Keeper) EnclaveClientRemoveCredential(sdkctx sdk.Context, credential types.Credential, requesterWalletID string) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "RemoveCredential not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.RemoveCredential(ctx, &types.EnclaveRemoveCredentialRequest{
		Credential:        &credential,
		RequesterWalletID: requesterWalletID,
	})
	if err != nil {
		c.ContextError(sdkctx, "error returned by RemoveCredential on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "RemoveCredential returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientClaimCredential(sdkctx sdk.Context, claimCredential *types.MsgClaimCredential) (*types.MsgClaimCredentialResponse, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ClaimCredential not called in checktx")
		return &types.MsgClaimCredentialResponse{}, nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ClaimCredential(ctx, claimCredential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ClaimCredential on enclave "+err.Error())
		return nil, err
	}
	c.ContextDebug(sdkctx, "ClaimCredential returned ok")
	return r, nil
}

// EnclaveClientUpdateCredential stamps the block height and the module params into the request
// rather than letting the client supply them: the change policy is evaluated inside the enclave
// and its verdict has to be identical on every validator.
func (k Keeper) EnclaveClientUpdateCredential(sdkctx sdk.Context, updateCredential *types.MsgUpdateCredential, params types.Params) (*types.MsgUpdateCredentialResponse, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "UpdateCredential not called in checktx")
		return &types.MsgUpdateCredentialResponse{}, nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.UpdateCredential(ctx, &types.EnclaveUpdateCredentialRequest{
		Msg:         updateCredential,
		BlockHeight: sdkctx.BlockHeight(),
		Params:      params,
	})
	if err != nil {
		c.ContextError(sdkctx, "error returned by UpdateCredential on enclave "+err.Error())
		return nil, err
	}
	c.ContextDebug(sdkctx, "UpdateCredential returned ok")
	return r, nil
}

func (k Keeper) EnclaveClientClaimUpdatedCredential(sdkctx sdk.Context, msg *types.MsgClaimUpdatedCredential) (*types.MsgClaimUpdatedCredentialResponse, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ClaimUpdatedCredential not called in checktx")
		return &types.MsgClaimUpdatedCredentialResponse{}, nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ClaimUpdatedCredential(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ClaimUpdatedCredential on enclave "+err.Error())
		return nil, err
	}
	c.ContextDebug(sdkctx, "ClaimUpdatedCredential returned ok")
	return r, nil
}

func (k Keeper) EnclaveClientQueryGetSubWalletIDByOriginalWalletID(credential types.Credential) string {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryGetSubWalletIDByOriginalWalletID(ctx, &credential)
	if err != nil {
		fmt.Println("error returned by QueryGetSubWalletIDByOriginalWalletID on enclave", err)
		return ""
	}
	fmt.Println("QueryGetSubWalletIDByOriginalWalletID returns", r.SubWalletID)
	return r.SubWalletID
}

func (k Keeper) EnclaveClientRecoverKeyByCredential(sdkctx sdk.Context, credential types.Credential) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "RecoverKeyByCredential not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.RecoverKeyByCredential(ctx, &credential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by RecoverKeyByCredential on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "RecoverKeyByCredential returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSignRecoverKey(sdkctx sdk.Context, signRecoverKey types.MsgSignRecoverPrivateKey) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SignRecoverKey not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SignRecoverKey(ctx, &signRecoverKey)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SignRecoverKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SignRecoverKey returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetPublicKey(sdkctx sdk.Context, publicKey types.PublicKey) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetPublicKey not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetPublicKey(ctx, &publicKey)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetPublicKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetPublicKey returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetIntervalPublicKeyId(sdkctx sdk.Context, intervalPublicKeyId types.IntervalPublicKeyID) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetIntervalPublicKeyID not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetIntervalPublicKeyID(ctx, &intervalPublicKeyId)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetIntervalPublicKeyId on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetIntervalPublicKeyId returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetPioneerJar(sdkctx sdk.Context, pioneerJar types.PioneerJar) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetPioneerJar not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetPioneerJar(ctx, &pioneerJar)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetPioneerJar on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetIntervalPublicKeyId returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetJarRegulator(sdkctx sdk.Context, jarRegulator types.JarRegulator) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetJarRegulator not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetJarRegulator(ctx, &jarRegulator)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetJarRegulator on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetJarRegulator returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientBroadcastSecretSharePrivateKey(sdkctx sdk.Context, key types.SecretSharePrivK) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetSecretSharePrivateKey not called in checktx")
		return nil
	}

	ctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.SetSecretSharePrivateKey(ctx, &key)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetSecretSharePrivateKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetSecretSharePrivateKey returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

var synchronizedWithEnclave = false

// set by reconcileEnclaveHeight when startup found chain and enclave already at the same height
// (cases A/B) -- in which case a store mismatch found afterwards is divergence, not seeding
var enclaveHeightsAgreedAtStartup = false

// set by reconcileEnclaveHeight for case F, and acted on by EnclaveBeginBlock once the mirror push
// has seeded the tables the fetch depends on
var (
	needsPrivateStateSync  = false
	privateStateSyncHeight int64
)

// reconcileEnclaveHeight compares the enclave's height watermarks against the chain's committed
// height at startup and repairs what it can.  Runs once per process, from the first BeginBlock
// (app.New cannot host it: InitEnclave runs there BEFORE app.Load, so the chain's committed
// height is not yet known).
//
// With C = the chain's last committed height (header.Height - 1), the cases are:
//
//	A. prepared == C, confirmed == C   healthy; nothing to do.
//	B. prepared == C, confirmed  < C   crash between the enclave's EndBlock prepare and the
//	                                   chain's post-commit confirm.  The state is right on both
//	                                   sides; only the watermark lags.  Confirm it.
//	C. prepared  > C                   crash between the enclave's prepare and BaseApp.Commit,
//	                                   or a chain-only rollback.  Comet will NOT replay the
//	                                   divergent block (its handshake sees appHeight ==
//	                                   storeHeight), so without this the enclave's extra state
//	                                   is permanent and invisible.  Roll the enclave back to C;
//	                                   the chain then re-executes forward normally.
//	D. 0 < prepared < C                the enclave missed blocks the chain has already
//	                                   committed.  They will never be replayed, so nothing can
//	                                   be repaired in place: HALT, naming the remedy
//	                                   (qadenad rollback --height <prepared>, which moves chain
//	                                   and enclave together).  Deliberately NOT papered over
//	                                   with enclaveSynchronizeStores -- that pushes only the
//	                                   nine mirror prefixes and would leave every
//	                                   enclave-private prefix (uniqueness index, AML window,
//	                                   sub-wallet maps) silently stale while making the store
//	                                   hashes agree, which is worse than halting because it
//	                                   looks fixed.
//	E. prepared == 0, C == 0           a genuinely fresh enclave on a chain that has committed
//	                                   nothing.  Nothing to reconcile: its first EndBlock adopts
//	                                   whatever height it arrives at (see the prepared==0
//	                                   exemption there), and the store push that follows this
//	                                   call seeds the mirrors.  A node joining by BLOCK-SYNC
//	                                   arrives here -- its chain starts at 0 and it rebuilds
//	                                   every private table by executing each block.
//	F. prepared == 0, C  > 0           a fresh or wiped enclave on a chain that ALREADY HAS
//	                                   HISTORY.  HALT.  The store push seeds only the nine
//	                                   mirrors; every enclave-private table stays empty, and an
//	                                   empty AML window reaches different accept/reject verdicts
//	                                   than the rest of the network -- a silent fork.  Reached
//	                                   by a state-synced node (restores state at H without
//	                                   executing 1..H) or by an enclave data directory wiped
//	                                   while the chain's was kept.
//
//	                                   This case is what the enclave private-state transfer
//	                                   will eventually service: fetch the private tables at C
//	                                   from a peer, then continue.  Until then the only correct
//	                                   move is to refuse to start.
//
// heightVerdict is the classification half of reconcileEnclaveHeight, split out from the acting
// half so it can be tested without a header service, a gRPC client or a live enclave behind it.
// The distinction that most needs pinning is fresh-vs-stranded: a node joining by BLOCK-SYNC and a
// node restored by STATE-SYNC both arrive with prepared == 0, and the only thing separating "seed
// me normally" from "you are about to fork" is whether the chain already has committed history.
type heightVerdict int

const (
	verdictFresh         heightVerdict = iota // E: nothing anywhere yet; seed normally
	verdictHealthy                            // A: prepared == confirmed == chain
	verdictConfirmOnly                        // B: state agrees, confirm watermark lags
	verdictRollback                           // C: enclave ahead of the chain
	verdictHaltNoHistory                      // F: fresh enclave, chain already has history
	verdictHaltBehind                         // D: enclave behind; blocks will never replay
)

func classifyEnclaveHeight(prepared, confirmed, chainHeight int64) heightVerdict {
	switch {
	case prepared == 0 && chainHeight == 0:
		return verdictFresh
	case prepared == 0:
		return verdictHaltNoHistory
	case prepared == chainHeight && confirmed == chainHeight:
		return verdictHealthy
	case prepared == chainHeight && confirmed < chainHeight:
		return verdictConfirmOnly
	case prepared > chainHeight:
		return verdictRollback
	default:
		return verdictHaltBehind
	}
}

func (k Keeper) reconcileEnclaveHeight(sdkCtx sdk.Context) {
	chainHeight := k.headerService.GetHeaderInfo(sdkCtx).Height - 1

	h, err := k.EnclaveGetHeight(sdkCtx)
	haltOnEnclaveFailure(sdkCtx, "height reconciliation", err)

	switch classifyEnclaveHeight(h.PreparedHeight, h.ConfirmedHeight, chainHeight) {
	case verdictFresh:
		// case E -- fresh enclave, chain with no history; first EndBlock adopts, store push seeds
		c.ContextInfo(sdkCtx, fmt.Sprintf("Qadena: enclave has no committed height; it will adopt chain height %d at its first EndBlock", chainHeight+1))

	case verdictHaltNoHistory:
		// case F -- fresh or wiped enclave, chain already has history.  The private tables can be
		// fetched from a peer, but NOT from here: that needs EnclaveIdentity (to attest the peer)
		// and IntervalPublicKeyID (to find one), and both arrive with the store push that runs
		// after this function.  So record the need and let EnclaveBeginBlock act on it once the
		// mirrors are seeded; if the fetch fails or is impossible, that is where the node halts.
		needsPrivateStateSync = true
		privateStateSyncHeight = chainHeight
		c.ContextError(sdkCtx, fmt.Sprintf("Qadena: enclave holds no private state but the chain has committed height %d -- will fetch it from a peer before executing block %d", chainHeight, chainHeight+1))

	case verdictHealthy:
		// case A -- healthy
		enclaveHeightsAgreedAtStartup = true
		c.ContextInfo(sdkCtx, fmt.Sprintf("Qadena: enclave is reconciled at height %d", chainHeight))

	case verdictConfirmOnly:
		// case B -- crash in the confirm window; state agrees, watermark lags
		enclaveHeightsAgreedAtStartup = true
		c.ContextInfo(sdkCtx, fmt.Sprintf("Qadena: enclave prepared height %d was never confirmed (confirmed %d); confirming now", h.PreparedHeight, h.ConfirmedHeight))
		err := k.EnclaveConfirmHeight(chainHeight)
		haltOnEnclaveFailure(sdkCtx, "height reconciliation (confirm)", err)

	case verdictRollback:
		// case C -- enclave ahead; roll it back and let the chain re-execute forward
		c.ContextError(sdkCtx, fmt.Sprintf("Qadena: enclave is at height %d, AHEAD of the chain's %d -- rolling the enclave back", h.PreparedHeight, chainHeight))
		r, err := k.EnclaveRollbackToHeight(sdkCtx, chainHeight, false)
		haltOnEnclaveFailure(sdkCtx, "height reconciliation (rollback)", err)
		if !r.RolledBack {
			// "already at height" cannot happen on this branch; anything else here means the
			// rollback did not happen and continuing would commit against divergent state
			haltOnEnclaveFailure(sdkCtx, "height reconciliation (rollback)", fmt.Errorf("enclave did not roll back: %s", r.Reason))
		}
		c.ContextInfo(sdkCtx, fmt.Sprintf("Qadena: enclave rolled back from height %d to %d; the chain will re-execute forward", h.PreparedHeight, chainHeight))

	default:
		// case D -- enclave behind; the missing blocks will never be replayed.
		//
		// Two remedies, because the first one is not always possible: `qadenad rollback` needs the
		// chain to still hold state at the target height, and a node that joined by state-sync has
		// no history below the height it joined at.  Detecting which case applies would mean
		// reaching the block store's base height from inside the keeper, which there is no clean
		// path to -- so name both and let the operator see which one their node can do.
		panic(fmt.Sprintf(
			"qadena: the enclave is at height %d but this chain has already committed height %d.\n"+
				"\n"+
				"The missing blocks will not be replayed, so this cannot be repaired in place.  Stop the node,\n"+
				"then either:\n"+
				"\n"+
				"  * roll chain and enclave back together, if this node still holds chain state at %d:\n"+
				"        qadenad rollback --height %d\n"+
				"\n"+
				"  * or, if it does not -- a node that joined by state-sync has no history below its join\n"+
				"    height -- discard this node's chain AND enclave data and re-join from scratch.  Do not\n"+
				"    discard only one of them: that produces the fresh-enclave-on-an-established-chain state,\n"+
				"    which halts for the same underlying reason.",
			h.PreparedHeight, chainHeight, h.PreparedHeight, h.PreparedHeight))
	}
}

// fetchEnclavePrivateState pulls the enclave-private tables at height H from a peer, and HALTS the
// node if it cannot.  Halting is the whole point: the alternative is executing block H+1 against an
// empty AML window, reaching different verdicts than the network, and forking silently.
func (k Keeper) fetchEnclavePrivateState(sdkCtx sdk.Context, height int64) {
	// THE HEIGHT MUST BE THE CHAIN'S LAST COMMITTED ONE -- the height state-sync stopped at, which
	// is also the height block-sync is about to continue from.  Everything downstream depends on it:
	// the peer pins its store to that version, the AML window is pruned relative to it, and this
	// node's very next act is to execute height+1 against what arrives.
	//
	// Off by one in either direction is a silent fork rather than an error.  Fetching height-1 would
	// leave out whatever block H did to the window; fetching height+1 would include a block this
	// node is about to execute for itself, double-counting it.
	//
	// Asserted rather than assumed because the value is derived in reconcileEnclaveHeight and
	// consumed here, with the store push in between -- two functions and a package-level variable
	// apart, which is exactly the distance over which an invariant quietly stops holding.
	if committed := k.headerService.GetHeaderInfo(sdkCtx).Height - 1; height != committed {
		panic(fmt.Sprintf(
			"qadena: private-state fetch height %d is not the chain's last committed height %d -- refusing to seed the enclave at the wrong height",
			height, committed))
	}

	peers := k.enclavePrivateStatePeers(sdkCtx)
	if len(peers) == 0 {
		panic(fmt.Sprintf(
			"qadena: this enclave holds no private state at height %d and no peer is reachable to supply it.\n"+
				"\n"+
				"No IntervalPublicKeyID record carries an external address, so there is nobody to ask.  Start\n"+
				"the node with at least one reachable pioneer that has been running since before height %d, or\n"+
				"re-join with state-sync disabled so this node block-syncs and rebuilds the private tables by\n"+
				"executing every block.", height, height))
	}

	// The window and the block time come from OUR chain state, not the peer's: policy reaches an
	// enclave per-message from the chain, so a peer asked for a historical view has no window value
	// of its own.  Using the current header's time is right rather than approximate -- block time
	// only moves forward, so an entry outside the window now is one the very next scan of that
	// wallet would drop before computing anything.
	params := k.GetParams(sdkCtx)
	header := k.headerService.GetHeaderInfo(sdkCtx)

	reply, err := k.EnclaveSyncPrivateState(sdkCtx, &types.MsgSyncPrivateState{
		Height:        height,
		WindowSeconds: params.SuspiciousTransactionWindowSeconds,
		BlockTimeUnix: header.Time.Unix(),
		Peers:         peers,
	})
	if err != nil {
		panic(fmt.Sprintf(
			"qadena: could not fetch enclave-private state at height %d: %v\n"+
				"\n"+
				"Continuing would execute block %d against an empty AML window, which reaches different\n"+
				"accept/reject verdicts than the rest of the network and forks.  Check that a pioneer running\n"+
				"since before height %d is reachable from this node, then restart -- the import resumes from\n"+
				"where it stopped.  Failing that, re-join with state-sync disabled.",
			height, err, height+1, height))
	}

	c.ContextInfo(sdkCtx, fmt.Sprintf("Qadena: imported enclave-private state at height %d from %s (%d rows, %d pages)",
		reply.GetHeight(), reply.GetServedBy(), reply.GetRows(), reply.GetPages()))
}

// enclavePrivateStatePeers lists peer chain RPC endpoints that might serve private state.
//
// Ordered DETERMINISTICALLY.  The content served is height-pinned and therefore identical from any
// correct peer, so which one answers cannot change the result -- but a stable order makes a failure
// reproducible, which is worth more during an incident than any load spreading would be.
func (k Keeper) enclavePrivateStatePeers(sdkCtx sdk.Context) []string {
	seen := map[string]bool{}
	var peers []string
	for _, ipki := range k.GetAllIntervalPublicKeyID(sdkCtx) {
		addr := ipki.ExternalIPAddress
		if addr == "" || seen[addr] {
			continue
		}
		seen[addr] = true
		peers = append(peers, addr)
	}
	sort.Strings(peers)
	return peers
}

func (k Keeper) EnclaveBeginBlock(sdkCtx sdk.Context) {
	reportSlowEnclaveCalls(sdkCtx)

	if !synchronizedWithEnclave {
		// Height reconciliation FIRST, store synchronization second: the store push is only
		// meaningful once chain and enclave agree what height they are at -- pushing rows into an
		// enclave that is ahead would make the hashes agree while its state stays wrong.
		k.reconcileEnclaveHeight(sdkCtx)
		err := k.enclaveSynchronizeStores(sdkCtx)
		if err != nil {
			c.ContextError(sdkCtx, "Qadena: enclaveSynchronizeStores failed: "+err.Error())
		} else {
			// Private-state import goes HERE and nowhere else in this function.  It has to follow
			// the store push, which seeds EnclaveIdentity (needed to attest a peer) and
			// IntervalPublicKeyID (needed to find one), and it has to precede any transaction of
			// this block, because the AML window is read during execution.  BeginBlock is the only
			// point that satisfies both.
			if needsPrivateStateSync {
				k.fetchEnclavePrivateState(sdkCtx, privateStateSyncHeight)
				needsPrivateStateSync = false
			}
			synchronizedWithEnclave = true
		}
	}

	header := k.headerService.GetHeaderInfo(sdkCtx)
	blockInfo := k.cometService.GetCometBlockInfo(sdkCtx)

	currentBlockHeader = header

	//  fmt.Println("HEADER", c.PrettyPrint(header))

	if header.Height%11 == 0 {
		ctx, cancel := enclaveExecContext()
		defer cancel()
		proposerAddress := strings.ToUpper(hex.EncodeToString(blockInfo.GetProposerAddress()))
		//    fmt.Println("ProposerAddress", proposerAddress)
		//    fmt.Println("My ValidatorAddress", validatorAddress)
		_, _ = EnclaveGRPCClient.UpdateHeight(ctx, &types.MsgUpdateHeight{Height: header.Height, IsProposer: proposerAddress == validatorAddress})
	}
}

func (k Keeper) EnclaveInvokeEndBlock(sdkctx sdk.Context) {
	ctx, cancel := enclaveExecContext()
	defer cancel()
	// This RPC is what makes the enclave's block durable -- its handler commits the enclave's
	// store.  The error used to be discarded here while the four Sync* calls above halt the node
	// on failure, which is exactly backwards: an enclave that cannot COMMIT is at least as
	// dangerous as one that cannot sync, because the next block then executes against enclave
	// state that was never persisted, and an enclave restart replays from a version this chain
	// has already moved past.  Same failure, same answer: halt this node, not the chain.
	//
	// The height rides along so the enclave can stamp the version it commits and index
	// height->version for rollback (see enclave_height.go in cmd/qadenad_enclave).
	r, err := EnclaveGRPCClient.EndBlock(ctx, &types.MsgEndBlock{Height: sdkctx.BlockHeight()})
	haltOnEnclaveFailure(sdkctx, "end block", err)

	// The reply carries the accumulators the enclave just committed for this block; compare them
	// against the chain's own, every block.  See comparePerBlockAccumulators.
	k.comparePerBlockAccumulators(sdkctx, r.GetAccumulators())
}

// EnclaveGetHeight reads the enclave's height watermarks: prepared (last height whose writes its
// store has committed), confirmed (last height the chain acknowledged as durable), plus its raw
// IAVL version, rollback horizon and on-disk schema.  This is the basis for startup
// reconciliation between chain and enclave.
func (k Keeper) EnclaveGetHeight(sdkctx sdk.Context) (*types.GetEnclaveHeightReply, error) {
	ctx, cancel := enclaveExecContext()
	defer cancel()
	r, err := EnclaveGRPCClient.GetEnclaveHeight(ctx, &types.MsgGetEnclaveHeight{})
	if err != nil {
		c.ContextError(sdkctx, "error returned by GetEnclaveHeight on enclave "+err.Error())
		return nil, err
	}
	return r, nil
}

// EnclaveRollbackTimeout bounds a RollbackToHeight call.  Deliberately NOT c.DebugTimeout: the
// enclave's LoadVersionForOverwriting deletes every version above the target and rebuilds the
// fast-node index, so a deep rollback legitimately takes minutes.
const EnclaveRollbackTimeout = 30 * time.Minute

// EnclavePrivateStateSyncTimeout bounds a whole private-state import.  Also not c.DebugTimeout: the
// enclave pulls the AML window and identity indexes from a peer a page at a time over the network,
// committing each page, so a real import is many round trips rather than one local call.  Cutting
// it short mid-transfer would not corrupt anything -- the import resumes from its recorded cursor --
// but it would stall the node's join behind a needless retry.
const EnclavePrivateStateSyncTimeout = 60 * time.Minute

// EnclaveConfirmHeight tells the enclave the chain has durably committed the given height -- the
// second phase of the two-phase commit, called from the app.Commit override in app/app.go AFTER
// BaseApp.Commit returns.  Runs outside any block, so it takes no sdk.Context.
func (k Keeper) EnclaveConfirmHeight(height int64) error {
	ctx, cancel := enclaveExecContext()
	defer cancel()
	_, err := EnclaveGRPCClient.ConfirmHeight(ctx, &types.MsgConfirmHeight{Height: height})
	return err
}

// EnclaveRollbackToHeight rewinds the enclave's versioned store to the given chain height.
// Refusals (enclave behind the target, height below the rollback horizon) come back as errors;
// "already at that height" and dry runs come back as a reply with RolledBack=false.
func (k Keeper) EnclaveRollbackToHeight(sdkctx sdk.Context, height int64, dryRun bool) (*types.RollbackToHeightReply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), EnclaveRollbackTimeout)
	defer cancel()
	r, err := EnclaveGRPCClient.RollbackToHeight(ctx, &types.MsgRollbackToHeight{Height: height, DryRun: dryRun})
	if err != nil {
		c.ContextError(sdkctx, "error returned by RollbackToHeight on enclave "+err.Error())
		return nil, err
	}
	return r, nil
}

// Outbox drains are PAGED, so each of these loops until the enclave says the queue is empty.
//
// ALL PAGES MUST BE DRAINED WITHIN THIS BLOCK.  The enclave clears each page through its
// transaction cache, so the clears become durable together when the block commits -- at the same
// moment the chain writes the rows those pages carried.  Stopping partway and resuming in a later
// block would apply rows whose queue entries then survive, and deliver them twice.
//
// See MsgSyncWallets for why the enclave bounds a page at all: it resolves every queued ID into a
// full row and holds the page in the EPC, so an unbounded drain would make its peak memory a
// function of how busy the block was.

// outboxDrainMaxPages bounds the loop so a misbehaving enclave stalls the node instead of spinning
// forever.  At a megabyte a page this is 256 MiB of queued rows in a SINGLE block -- unreachable by
// any real workload, which is the point: crossing it means `more` is stuck true, not that the chain
// is busy.  The enclave only ever reports `more` after consuming entries, so a healthy queue
// strictly shrinks.
const outboxDrainMaxPages = 256

func (k Keeper) EnclaveSyncWallets(sdkctx sdk.Context) (error, []*types.Wallet) {
	var wallets []*types.Wallet

	for page := 0; ; page++ {
		if page >= outboxDrainMaxPages {
			err := fmt.Errorf("SyncWallets did not drain after %d pages (%d rows so far) -- "+
				"the enclave keeps reporting more work", outboxDrainMaxPages, len(wallets))
			c.ContextError(sdkctx, err.Error())
			return err, nil
		}

		ctx, cancel := enclaveExecContext()
		r, err := EnclaveGRPCClient.SyncWallets(ctx, &types.MsgSyncWallets{Clear: true, MaxBytes: drainMaxBytes})
		cancel()
		if err != nil {
			c.ContextError(sdkctx, "error returned by SyncWallets on enclave "+err.Error())
			return err, nil
		}

		wallets = append(wallets, r.GetWallets()...)
		if !r.GetMore() {
			break
		}
	}

	if len(wallets) > 0 {
		c.ContextDebug(sdkctx, "SyncWallets returns ", c.PrettyPrint(wallets))
	}
	return nil, wallets
}

// EnclaveSyncCredentials drains the enclave's pending credential changes.  Removals come back
// separately from writes: an enclave-originated deletion has no other way to reach the chain,
// because SetCredentialNoEnclave can only write.
func (k Keeper) EnclaveSyncCredentials(sdkctx sdk.Context) (error, []*types.Credential, []*types.CredentialRef) {
	var credentials []*types.Credential
	var removed []*types.CredentialRef

	// One `more` covers BOTH queues -- changed and removed share a reply and a budget -- so the
	// loop keeps going while either has work left.
	for page := 0; ; page++ {
		if page >= outboxDrainMaxPages {
			err := fmt.Errorf("SyncCredentials did not drain after %d pages (%d changed, %d removed so far) -- "+
				"the enclave keeps reporting more work", outboxDrainMaxPages, len(credentials), len(removed))
			c.ContextError(sdkctx, err.Error())
			return err, nil, nil
		}

		ctx, cancel := enclaveExecContext()
		r, err := EnclaveGRPCClient.SyncCredentials(ctx, &types.MsgSyncCredentials{Clear: true, MaxBytes: drainMaxBytes})
		cancel()
		if err != nil {
			c.ContextError(sdkctx, "error returned by SyncCredentials on enclave "+err.Error())
			return err, nil, nil
		}

		credentials = append(credentials, r.GetCredentials()...)
		removed = append(removed, r.GetRemovedCredentials()...)
		if !r.GetMore() {
			break
		}
	}

	if len(credentials) > 0 {
		c.ContextDebug(sdkctx, "SyncCredentials returns", credentials)
	}
	if len(removed) > 0 {
		c.ContextDebug(sdkctx, "SyncCredentials removed", removed)
	}
	return nil, credentials, removed
}

func (k Keeper) EnclaveSyncRecoverKeys(sdkctx sdk.Context) (error, []*types.RecoverKey) {
	var recoverKeys []*types.RecoverKey

	for page := 0; ; page++ {
		if page >= outboxDrainMaxPages {
			err := fmt.Errorf("SyncRecoverKeys did not drain after %d pages (%d rows so far) -- "+
				"the enclave keeps reporting more work", outboxDrainMaxPages, len(recoverKeys))
			c.ContextError(sdkctx, err.Error())
			return err, nil
		}

		ctx, cancel := enclaveExecContext()
		r, err := EnclaveGRPCClient.SyncRecoverKeys(ctx, &types.MsgSyncRecoverKeys{Clear: true, MaxBytes: drainMaxBytes})
		cancel()
		if err != nil {
			c.ContextError(sdkctx, "error returned by SyncRecoverKeys on enclave "+err.Error())
			return err, nil
		}

		recoverKeys = append(recoverKeys, r.GetRecoverKeys()...)
		if !r.GetMore() {
			break
		}
	}

	if len(recoverKeys) > 0 {
		c.ContextDebug(sdkctx, "SyncRecoverKeys returns", recoverKeys)
	}
	return nil, recoverKeys
}

func (k Keeper) EnclaveSyncSuspiciousTransactions(sdkctx sdk.Context) (error, []*types.SuspiciousTransaction) {
	var suspicious []*types.SuspiciousTransaction

	for page := 0; ; page++ {
		if page >= outboxDrainMaxPages {
			err := fmt.Errorf("SyncSuspiciousTransactions did not drain after %d pages (%d rows so far) -- "+
				"the enclave keeps reporting more work", outboxDrainMaxPages, len(suspicious))
			c.ContextError(sdkctx, err.Error())
			return err, nil
		}

		ctx, cancel := enclaveExecContext()
		r, err := EnclaveGRPCClient.SyncSuspiciousTransactions(ctx, &types.MsgSyncSuspiciousTransactions{Clear: true, MaxBytes: drainMaxBytes})
		cancel()
		if err != nil {
			c.ContextError(sdkctx, "error returned by SyncSuspiciousTransactions on enclave "+err.Error())
			return err, nil
		}

		suspicious = append(suspicious, r.GetSuspiciousTransactions()...)
		if !r.GetMore() {
			break
		}
	}

	if len(suspicious) > 0 {
		c.ContextDebug(sdkctx, "SyncSuspiciousTransactions returns", suspicious)
	}
	return nil, suspicious
}

func (k Keeper) EnclaveValidateDestinationWallet(sdkctx sdk.Context, msg *types.MsgCreateWallet) (int, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateDestinationWallet not called in checktx")
		return types.WalletTypeCheckTx, nil
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateDestinationWallet(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateDestinationWallet on enclave "+err.Error())
		return types.WalletTypeUnknown, err
	}
	return int(r.Status), nil
}

func (k Keeper) EnclaveValidateCredential(sdkctx sdk.Context, msg *types.MsgBindCredential) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateCredential not called in checktx")
		return true, nil
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateCredential(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateCredential on enclave "+err.Error())
		return false, err
	}
	return r.Status, nil
}

// EnclaveValidatePersonalInfo asks the enclave to decrypt a freshly submitted credential and check
// the fields the identity hash is built from.  Returns a wrapped ErrInvalidPersonalInfo naming the
// broken rule -- the enclave sends back a code, never the offending value, because the transaction
// error it ends up in is public.
//
// Unlike the other Validate* hooks this one DOES run in CheckTx.  The whole point is to reject the
// submission where the identity provider is still the party being answered, and a check skipped in
// CheckTx would not surface during the CLI's --gas auto simulation -- the provider would get a
// successful-looking broadcast and discover the failure only in the block result.
func (k Keeper) EnclaveValidatePersonalInfo(sdkctx sdk.Context, msg *types.MsgCreateCredential) error {
	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidatePersonalInfo(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidatePersonalInfo on enclave "+err.Error())
		return err
	}

	if !r.Status {
		reason := c.PersonalInfoReason(r.Reason)
		c.ContextError(sdkctx, "personal info rejected: "+reason.Message())
		return errorsmod.Wrap(types.ErrInvalidPersonalInfo, reason.Message())
	}

	return nil
}

func (k Keeper) EnclaveValidateTransferPrime(sdkctx sdk.Context, msg *types.MsgTransferFunds) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateTransferPrime not called in checktx")
		return true, nil
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateTransferPrime(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateTransferPrime on enclave "+err.Error())
		st := status.Convert(err)
		if st.Code() == codes.Unauthenticated {
			err = types.ErrMismatchCredential
		}
		return false, err
	}
	return r.UpdateSourceWallet, nil
}

func (k Keeper) EnclaveScanTransaction(sdkctx sdk.Context, msg *types.MsgTransferFunds, conversion math.LegacyDec) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ScanTransaction not called in checktx")
		return true, nil
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	// The policy travels with the scan rather than being fixed at enclave startup, so a governance
	// change to the window, the thresholds or the eKYC gate takes effect without restarting nodes.
	params := k.GetParams(sdkctx)

	defaultThreshold, countryThresholds, err := k.SuspiciousThresholdTable(sdkctx, params)
	if err != nil {
		// fail closed, exactly as an unpriceable transfer does above: a transfer that cannot be
		// measured against a threshold must not settle unmeasured
		c.ContextError(sdkctx, "ScanTransaction: cannot resolve thresholds, refusing to scan: "+err.Error())
		return false, err
	}

	stx := &types.MsgScanTransactions{
		Timestamp:               currentBlockHeader.Time,
		Height:                  currentBlockHeader.Height,
		Msg:                     msg,
		Exchangerate:            conversion.String(),
		Params:                  params,
		CountryThresholds:       countryThresholds,
		DefaultThresholdAttoUSD: defaultThreshold,
	}
	r, err := EnclaveGRPCClient.ScanTransaction(grpcctx, stx)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ScanTransaction on enclave "+err.Error())
		return false, err
	}
	return r.Status, nil
}

func (k Keeper) EnclaveValidateTransferDoublePrime(sdkctx sdk.Context, msg *types.MsgReceiveFunds) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateTransferDoublePrime not called in checktx")
		return true, nil
	}

	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateTransferDoublePrime(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateTransferDoublePrime on enclave "+err.Error())
		return false, err
	}
	return r.UpdateDestinationWallet, nil
}

func (k Keeper) EnclaveQuerySyncEnclave(sdkctx sdk.Context, msg *types.QueryEnclaveSyncEnclaveRequest) (error, *types.QueryEnclaveSyncEnclaveResponse) {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveSyncEnclave(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQuerySyncEnclave on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryPrivateState(sdkctx sdk.Context, msg *types.QueryEnclavePrivateStateRequest) (error, *types.QueryEnclavePrivateStateResponse) {
	ctx, cancel := enclavePeerContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclavePrivateState(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryEnclavePrivateState on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryPrivateStateAvailability(sdkctx sdk.Context, msg *types.QueryEnclavePrivateStateAvailabilityRequest) (error, *types.QueryEnclavePrivateStateAvailabilityResponse) {
	ctx, cancel := enclavePeerContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclavePrivateStateAvailability(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryEnclavePrivateStateAvailability on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

// EnclaveSyncPrivateState asks the local enclave to pull the private tables at a height from peers.
//
// The deadline is separate from and much longer than c.DebugTimeout: this is a bulk transfer of
// potentially many pages over the network, not a single local call, and inheriting the ordinary
// per-call timeout would abort a legitimate import partway through.
func (k Keeper) EnclaveSyncPrivateState(sdkctx sdk.Context, msg *types.MsgSyncPrivateState) (*types.SyncPrivateStateReply, error) {
	ctx, cancel := context.WithTimeout(context.Background(), EnclavePrivateStateSyncTimeout)
	defer cancel()

	r, err := EnclaveGRPCClient.SyncPrivateState(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SyncPrivateState on enclave "+err.Error())
		return nil, err
	}
	return r, nil
}

func (k Keeper) EnclaveQueryValidateEnclaveIdentity(sdkctx sdk.Context, msg *types.QueryEnclaveValidateEnclaveIdentityRequest) (error, *types.QueryEnclaveValidateEnclaveIdentityResponse) {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveValidateEnclaveIdentity(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQueryValidateEnclaveIdentity on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryFindCredential(sdkctx sdk.Context, msg *types.QueryFindCredentialRequest) (error, *types.QueryFindCredentialResponse) {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryFindCredential(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryFindCredential on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQuerySecretShare(sdkctx sdk.Context, msg *types.QueryEnclaveSecretShareRequest) (error, *types.QueryEnclaveSecretShareResponse) {
	ctx, cancel := enclavePeerContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveSecretShare(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQuerySecretShare on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryRecoverKeyShare(sdkctx sdk.Context, msg *types.QueryEnclaveRecoverKeyShareRequest) (error, *types.QueryEnclaveRecoverKeyShareResponse) {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveRecoverKeyShare(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryRecoverKeyShare on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryGetRecoverKey(sdkctx sdk.Context, msg *types.QueryGetRecoverKeyRequest) (error, *types.QueryGetRecoverKeyResponse) {
	ctx, cancel := enclaveQueryContext()
	defer cancel()

	r, err := EnclaveGRPCClient.QueryGetRecoverKey(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryGetRecoverKey on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (sdk.Context, error) {
	/*
		// don't do anything if we are simulating, if we are checking/re-checking the tx, or if we are at block 0 (genesis)
		var price uint64 = 500000000
		if !simulate && !ctx.IsCheckTx() && !ctx.IsReCheckTx() && ctx.BlockHeight() != 0 {
			feeTx, ok := tx.(sdk.FeeTx)
			if !ok {
				return ctx, errorsmod.Wrap(sdkerrors.ErrTxDecode, "Tx must be a FeeTx")
			}
			coins := feeTx.GetFee()
			// coins must be at least 1 elemen
			if len(coins) == 0 {
				c.ContextDebug(ctx, "no fee provided, using default gas price", price)
			} else {
				if coins[0].Denom != types.AQadenaTokenDenom {
					return ctx, errorsmod.Wrap(sdkerrors.ErrInsufficientFee, "must provide fee in aqdn")
				}

				// calculate gas price
				gas := math.NewIntFromUint64(feeTx.GetGas())

				// coins[0].Amount is the fee (in aqdn) that was already put into the fee collector
				price = coins[0].Amount.Quo(gas).Uint64()

				c.ContextDebug(ctx, "gas price", price)
			}
			k.BeginTransaction(ctx.Logger(), price)
		} else {
			// default gas price
			c.ContextDebug(ctx, "using default gas price", price)
			k.BeginTransaction(ctx.Logger(), price)
		}
	*/
	return next(ctx, tx, simulate)
}

func (k Keeper) PostHandle(ctx sdk.Context, tx sdk.Tx, simulate, success bool, next sdk.PostHandler) (newCtx sdk.Context, err error) {
	// don't do anything if we are simulating, if we are checking/re-checking the tx, or if we are at block 0 (genesis)
	if !simulate && !ctx.IsCheckTx() && !ctx.IsReCheckTx() && ctx.BlockHeight() != 0 {
		//		err := k.EndTransaction(ctx, ctx.Logger(), int64(ctx.GasMeter().GasRemaining()), success)
		err := k.EndTransaction(ctx, ctx.Logger(), success)
		if err != nil {
			return ctx, err
		}
	}
	return next(ctx, tx, simulate, success)
}

/*
func (k Keeper) RegisterCreator(creator string) error {
	if k.cachedCreator.Get() == "no-charge" {
		if k.cachedGasPriceInAQDN.Get() == 0 {
			return errors.New("cannot register creator " + creator + " when there is no gas price set")
		}
		k.cachedCreator.Set(creator)
	} else if k.cachedCreator.Get() != creator {
		return errors.New("cannot register creator " + creator + " when " + k.cachedCreator.Get() + " is already registered")
	}
	return nil
}
*/

/*
func (k Keeper) BeginTransaction(logger log.Logger, feeInAQDN uint64) {
	k.cachedCreator.Set("no-charge")
	k.cachedGasPriceInAQDN.Set(feeInAQDN)
}
*/

// func (k Keeper) EndTransaction(ctx sdk.Context, logger log.Logger, refundGas int64, success bool) error {
func (k Keeper) EndTransaction(ctx sdk.Context, logger log.Logger, success bool) error {
	// let the enclave know that the transaction is complete
	grpcctx, cancel := enclaveExecContext()
	defer cancel()

	tc := &types.MsgTransactionComplete{
		Success: success,
	}

	_, err := EnclaveGRPCClient.TransactionComplete(grpcctx, tc)
	if err != nil {
		c.ContextError(ctx, "error returned by EnclaveTransactionComplete on enclave "+err.Error())
		return err
	}

	/*
		// if the cachedCreator is "no-charge" then we don't need to refund the gas
		if k.cachedCreator.Get() != "no-charge" {
			// do the work to return the unused gas

			feeCollectorAddr := k.accountKeeper.GetModuleAddress(authtypes.FeeCollectorName)

			feecollector := k.bankKeeper.GetBalance(ctx, feeCollectorAddr, types.AQadenaTokenDenom)

			// display feecollector
			c.ContextDebug(ctx, "feecollector "+feecollector.String())

			// convert uint64 to string
			c.ContextDebug(ctx, "refundGas "+strconv.FormatInt(refundGas, 10))

			remainingGas := big.NewInt(refundGas)

			// multiply remainingGas by 1000000
			remainingGas = remainingGas.Mul(remainingGas, big.NewInt(int64(k.cachedGasPriceInAQDN.Get())))

			refundCoin, err := sdk.ParseCoinNormalized(remainingGas.String() + types.AQadenaTokenDenom)

			if err != nil {
				c.ContextError(ctx, "error parsing refundCoin "+err.Error())
				return err
			}

			c.ContextDebug(ctx, "cachedCreator ", k.cachedCreator.Get())

			creatorAddress, err := sdk.AccAddressFromBech32(k.cachedCreator.Get())

			if err != nil {
				c.ContextDebug(ctx, "Invalid creator "+k.cachedCreator.Get()+" "+err.Error())
				return types.ErrInvalidCreator
			}

			err = k.bankKeeper.SendCoinsFromModuleToAccount(ctx, authtypes.FeeCollectorName, creatorAddress, sdk.NewCoins(refundCoin))

			if err != nil {
				c.ContextError(ctx, "error refunding coins to app account "+err.Error())
				return err
			}

			feecollector = k.bankKeeper.GetBalance(ctx, feeCollectorAddr, types.AQadenaTokenDenom)

			// display feecollector
			c.ContextDebug(ctx, "feecollector after refund "+feecollector.String())
		}
	*/

	return nil
}
func (k Keeper) enclaveSynchronizeStores(sdkctx sdk.Context) error {
	c.ContextDebug(sdkctx, "Qadena: enclaveSynchronizeStores -- Chain initialized and ready for business, synchronizing enclave...")

	// THE DECISION RUNS ON ACCUMULATOR ROWS, not scans (backlog item 46).  The seam RPC is
	// establish-then-answer on the committed clock, so every mirrored store has a value; the
	// chain establishes its own below before comparing.  Ten 33-byte comparisons decide the
	// seeding; nothing scans unless a store actually needs establishing.
	ctx, cancel := enclaveExecContext()
	defer cancel()

	reply, err := EnclaveGRPCClient.GetStoreAccumulators(ctx, &types.MsgGetStoreAccumulators{})
	if err != nil {
		c.ContextError(sdkctx, "Qadena: enclaveSynchronizeStores error returned by GetStoreAccumulators on enclave "+err.Error())
		return err
	}

	checkSync := false

	// Push failures, counted per prefix.  Every one of these call sites used to discard the error.
	// That is not a theoretical loss: SetProtectKey and SetRecoverKey decrypt a vshare with a
	// HISTORICAL SS interval private key before they write anything, and obtaining one means an
	// attested round trip to each owner (getSSPrivK).  When that fails -- an owner unreachable, the
	// deadline on this whole call exhausted, a key whose owners have all rotated away -- the
	// handler returns early, so the enclave silently loses both the mirror row AND the derived
	// index the handler builds as a side effect (setProtectSubWalletIDByOriginalWalletID,
	// setRecoverOriginalWalletIDByNewWalletID).
	//
	// A half-seeded enclave that reports success is the exact failure mode this whole branch
	// exists to eliminate, so collect the failures and refuse to proceed with them.
	pushFailures := map[string]int{}

	// The reply preserves the enclave's storeHashKeys order, which is LOAD-BEARING for seeding:
	// EnclaveIdentity and IntervalPublicKeyID must arrive before ProtectKey and RecoverKey rows
	// can be applied.  Iterating the reply keeps that order without a second list.
	for _, e := range reply.GetAccumulators() {
		if !mirroredStores[e.GetKey()] {
			c.ContextDebug(sdkctx, "Qadena: enclaveSynchronizeStores Ignoring key="+e.GetKey()+" in Qadena module")
			continue
		}
		if !e.GetPresent() {
			return fmt.Errorf("enclaveSynchronizeStores: enclave returned no accumulator for %s -- "+
				"establish-then-answer makes this impossible; refusing to guess", e.GetKey())
		}

		chainAcc := k.EnsureStoreAccumulator(sdkctx, e.GetKey())

		if string(chainAcc[:]) == string(e.GetAcc()) {
			c.ContextDebug(sdkctx, "Qadena: enclaveSynchronizeStores in-sync store:  key="+e.GetKey()+" acc="+c.AccumulatorHex(chainAcc))
			continue
		}

		c.ContextError(sdkctx, "Qadena: enclaveSynchronizeStores OUT-OF-SYNC store:  key="+e.GetKey()+
			" enclave-acc="+fmt.Sprintf("%x", e.GetAcc())+" chain-acc="+c.AccumulatorHex(chainAcc))

		rows, failed := k.seedEnclaveStore(sdkctx, e.GetKey())
		if failed > 0 {
			pushFailures[e.GetKey()] += failed
		}
		if rows > 0 {
			checkSync = true
		}
	}

	if len(pushFailures) > 0 {
		// not "for k := range" -- k is the Keeper receiver here
		prefixes := make([]string, 0, len(pushFailures))
		for prefix := range pushFailures {
			prefixes = append(prefixes, prefix)
		}
		sort.Strings(prefixes)
		detail := ""
		for _, p := range prefixes {
			detail += fmt.Sprintf("\n    %s: %d row(s) rejected", p, pushFailures[p])
		}
		panic(fmt.Sprintf(
			"qadena: seeding the enclave from chain state did not complete.%s\n"+
				"\n"+
				"These rows are now missing from the enclave, and so are the private indexes their handlers\n"+
				"build as a side effect.  ProtectKey and RecoverKey are the usual casualties: both decrypt a\n"+
				"vshare with a historical SS interval private key before writing, and that key has to be\n"+
				"reconstructed from its owners over the network.\n"+
				"\n"+
				"Check that the pioneers owning the older interval keys are reachable from this node, then\n"+
				"restart it -- seeding runs again from the first block.  Continuing instead would leave this\n"+
				"enclave silently short of rows that the rest of the network has.",
			detail))
	}

	if checkSync {
		// A mismatch on a FRESH enclave is seeding, and expected.  A mismatch when chain and
		// enclave already agreed on their height is neither: the same blocks produced different
		// mirror state, which points at non-deterministic enclave execution, a partial wipe, or
		// tampering.  The push above has made the hashes agree again, but hashes agreeing is not
		// the same as the node being trustworthy -- say so, loudly and distinctly.
		if enclaveHeightsAgreedAtStartup {
			c.ContextError(sdkctx, "Qadena: ENCLAVE STORES DIVERGED AT AN AGREED HEIGHT -- the chain's copies were re-pushed, but this is not a normal reseed; investigate how this enclave's state came to differ before trusting this node")
		}
	}

	return nil
}

// haltOnEnclaveFailure stops this node when an enclave call fails during EndBlock.
//
// WHY A PANIC IS THE CORRECT RESPONSE, and logging is not.
//
// EndBlock is where the enclave's state is copied into the chain's: wallets, credentials, recover
// keys and suspicious transactions.  Those writes are part of the block, so they are part of the app
// hash.  If the enclave cannot be reached the sync returns an error and NO writes happen -- and the
// old code logged that and carried on, committing a block whose state is missing everything the
// enclave would have contributed.  A healthy peer computes a different app hash for the same block,
// which is a fork.
//
// That is not hypothetical.  A node's enclave died of an out-of-memory (see the memory limit note in
// cmd/qadenad_enclave/enclave.go) and this is what followed:
//
//	prevote step: consensus deems this block invalid; prevoting nil
//	  err="wrong Block.Header.AppHash. Expected 48905948..., got 2DBD2B2C..."  height=61068
//	CONSENSUS FAILURE!!!
//
// The peer halted, correctly.  The node with the dead enclave held 99% of the stake, finalised the
// bad block alone, and kept producing for another 12,000 blocks on state nothing else agreed with.
// Nothing reported a problem, because nothing else was looking: with a lopsided stake split the
// chain keeps making blocks regardless.  test_peer_agreement.sh is the only thing that catches it,
// and only when a second validator exists to disagree.
//
// Halting is strictly better.  A validator that cannot compute correct state must not publish state
// at all: the chain continues without it if the remaining validators hold more than 2/3, an operator
// sees a stopped node instead of silent corruption, and the node can rejoin once its enclave is back.
// A panic in EndBlock is how the SDK expresses that -- it stops this node without touching the block.
func haltOnEnclaveFailure(sdkctx sdk.Context, step string, err error) {
	if err == nil {
		return
	}

	// A cancelled call means the watchdog declared the enclave dead; report THAT.  Without this
	// the operator sees "context canceled", which is true and useless.  Checked via the root's
	// recorded cause rather than errors.Is(err, context.Canceled), because gRPC surfaces the
	// cancellation as a status error (codes.Canceled) that does not unwrap to context.Canceled --
	// and once the root is cancelled, EVERY exec-path call fails, so whenever a cause exists it
	// is the reason this call failed.
	if cause := context.Cause(EnclaveAliveContext()); cause != nil {
		err = cause
	}

	c.ContextError(sdkctx, "enclave "+step+" failed during EndBlock: "+err.Error())
	panic("qadena: enclave " + step + " failed during EndBlock at height " +
		strconv.FormatInt(sdkctx.BlockHeight(), 10) + ": " + err.Error() +
		" -- halting rather than committing a block without the enclave's state, which would fork the chain")
}

// EnclaveEndBlock drains the enclave's pending changes into the chain's stores and then tells the
// enclave to commit.
//
// INVARIANT: an enclave->chain row must be delivered at the height that PRODUCED it, never later.
//
// The rows drained here are written into block state, so they are part of this block's app hash --
// and at least one of them is height-ordered on the chain side (AppendSuspiciousTransaction
// auto-increments its ID).  A node that delivered a row at height H+1 which its peers delivered at
// H would compute a different app hash for both blocks: a fork, of exactly the kind
// test_peer_agreement.sh exists to catch.  So there is no such thing as "retry the delivery next
// block".  Either the row lands in the block that produced it, or that block must be re-executed
// from scratch -- which is why an enclave failure anywhere below is a halt (haltOnEnclaveFailure),
// and why enclave rollback re-executes blocks rather than re-delivering their rows.
func (k Keeper) EnclaveEndBlock(sdkctx sdk.Context) {
	err, changedWallets := k.EnclaveSyncWallets(sdkctx)

	haltOnEnclaveFailure(sdkctx, "wallet sync", err)

	for _, wallet := range changedWallets {
		k.SetWalletNoEnclave(sdkctx, *wallet)
	}

	err, changedCredentials, removedCredentials := k.EnclaveSyncCredentials(sdkctx)

	haltOnEnclaveFailure(sdkctx, "credential sync", err)

	for _, credential := range changedCredentials {
		k.SetCredentialNoEnclave(sdkctx, *credential)
	}

	for _, removed := range removedCredentials {
		k.RemoveCredentialNoEnclave(sdkctx, removed.CredentialID, removed.CredentialType)
	}

	err, changedRecoverKeys := k.EnclaveSyncRecoverKeys(sdkctx)

	haltOnEnclaveFailure(sdkctx, "recover key sync", err)

	for _, recoverKey := range changedRecoverKeys {
		k.SetRecoverKey(sdkctx, *recoverKey)
	}

	err, newSuspiciousTransactions := k.EnclaveSyncSuspiciousTransactions(sdkctx)

	haltOnEnclaveFailure(sdkctx, "suspicious transaction sync", err)

	for _, st := range newSuspiciousTransactions {
		k.AppendSuspiciousTransaction(sdkctx, *st)
	}

	// Establish any chain-side store accumulator that does not exist yet -- LAST, mirroring the
	// enclave, whose maintainAccumulators runs in its EndBlock just before commitCache.  Placed
	// after the drains so an establishing scan covers everything this block wrote, exactly as the
	// enclave's placement does.  One Get per mirrored store per block once established.  These
	// writes are consensus state -- see maintainStoreAccumulators for the upgrade property.
	k.maintainStoreAccumulators(sdkctx)

	// The every-Nth-block honesty audit, chain side: recompute each mirrored store's accumulator
	// from the block-end data and compare to the maintained row.  Same store, same context, same
	// instant, same arithmetic -- no clocks to misalign -- so a mismatch means the invariant is
	// genuinely violated (an unhooked write path, or corrupted data) and the reaction is a HALT,
	// not a repair: repair would either mask the defect forever or bless the corruption.
	//
	// DETERMINISTIC, AND THEREFORE CHAIN-WIDE: every node audits the same state at the same
	// height, so a chain-side violation halts all of them together.  That is the correct shape
	// for a broken state invariant -- it is morally a consensus failure -- but it is a property
	// to know, not to discover.
	k.auditStoreAccumulators(sdkctx)

	k.EnclaveInvokeEndBlock(sdkctx)
}
