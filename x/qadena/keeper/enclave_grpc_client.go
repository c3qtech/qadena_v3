package keeper

import (
	//	"fmt"

	//  "errors"

	//	"math/big"

	//	"errors"
	"fmt"
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

// this is called during "transfer" funds
func (k Keeper) ScanTransaction(sdkctx sdk.Context, msg *types.MsgTransferFunds) (bool, error) {
	//marketPrefix := "cn"
	token := msg.TokenDenom
	if token == types.AQadenaTokenDenom {
		token = types.QadenaTokenDenom
	} else if strings.HasPrefix(token, "erc20/") {
		//marketPrefix = "cw"
		meta, _ := k.bankKeeper.GetDenomMetaData(sdkctx, msg.TokenDenom)
		token = meta.Symbol
	}

	//marketID := marketPrefix + ":" + strings.ToLower(token) + ":usd"
	//	cp, err := k.pricefeedKeeper.GetCurrentPrice(sdkctx, marketID)
	var basePrice math.LegacyDec = math.LegacyNewDecFromBigInt(c.BigIntZero)

	/*
		if err != nil {
			basePrice = sdk.NewDecFromBigInt(c.BigIntZero)
		} else {
			basePrice = cp.Price
		}
	*/

	return k.EnclaveScanTransaction(sdkctx, msg, basePrice)
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

				ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
				defer cancel()

				r, err := greeterClient.SayHello(ctx, &types.HelloRequest{Name: "Pong"})
				if err != nil {
					c.LoggerError(k.logger, "Could not ping the enclave "+err.Error())
				} else {
					c.LoggerDebug(k.logger, "Greeting "+r.GetMessage())
					EnclaveGRPCClient = types.NewQadenaEnclaveClient(conn)
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
		c.LoggerError(sdkctx.Logger(), "error gunzipping remote report "+err.Error())
		return false
	}
	_, err = buf.ReadFrom(reader)
	if err != nil {
		c.LoggerError(sdkctx.Logger(), "error gunzipping remote report "+err.Error())
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

	c.ContextDebug(sdkctx, "ClientVerifyRemoteReport uniqueID: "+uniqueID+" signerID: "+signerID)
	enclaveIdentity, found := k.GetEnclaveIdentity(sdkctx, uniqueID)
	if !found {
		c.ContextError(sdkctx, "couldn't find enclave identity")
		return false
	}

	c.ContextDebug(sdkctx, "enclaveIdentity signerID: "+enclaveIdentity.SignerID+" status: "+enclaveIdentity.Status)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SetRecoverKey(ctx, &pk)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetRecoverKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetRecoverKey returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientSetCredential(sdkctx sdk.Context, credential types.Credential) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "SetCredential not called in checktx")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SetCredential(ctx, &credential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetCredential on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetCredential returns "+strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveClientRemoveCredential(sdkctx sdk.Context, credential types.Credential) error {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "RemoveCredential not called in checktx")
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.RemoveCredential(ctx, &credential)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.ClaimCredential(ctx, claimCredential)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ClaimCredential on enclave "+err.Error())
		return nil, err
	}
	c.ContextDebug(sdkctx, "ClaimCredential returned ok")
	return r, nil
}

func (k Keeper) EnclaveClientQueryGetSubWalletIDByOriginalWalletID(credential types.Credential) string {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SetSecretSharePrivateKey(ctx, &key)
	if err != nil {
		c.ContextError(sdkctx, "error returned by SetSecretSharePrivateKey on enclave "+err.Error())
		return err
	}
	c.ContextDebug(sdkctx, "SetSecretSharePrivateKey returns", strconv.FormatBool(r.GetStatus()))
	return nil
}

func (k Keeper) EnclaveBeginBlock(sdkCtx sdk.Context) {
	header := k.headerService.GetHeaderInfo(sdkCtx)
	blockInfo := k.cometService.GetCometBlockInfo(sdkCtx)

	currentBlockHeader = header

	//  fmt.Println("HEADER", c.PrettyPrint(header))

	if header.Height%11 == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
		defer cancel()
		proposerAddress := strings.ToUpper(hex.EncodeToString(blockInfo.GetProposerAddress()))
		//    fmt.Println("ProposerAddress", proposerAddress)
		//    fmt.Println("My ValidatorAddress", validatorAddress)
		_, _ = EnclaveGRPCClient.UpdateHeight(ctx, &types.MsgUpdateHeight{Height: header.Height, IsProposer: proposerAddress == validatorAddress})
	}
}

func (k Keeper) EnclaveInvokeEndBlock(sdkctx sdk.Context) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()
	_, _ = EnclaveGRPCClient.EndBlock(ctx, &types.MsgEndBlock{})
}

func (k Keeper) EnclaveSyncWallets(sdkctx sdk.Context) (error, []*types.Wallet) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SyncWallets(ctx, &types.MsgSyncWallets{Clear: true})
	if err != nil {
		c.ContextError(sdkctx, "error returned by SyncWallets on enclave "+err.Error())
		return err, nil
	}
	if len(r.GetWallets()) > 0 {
		c.ContextDebug(sdkctx, "SyncWallets returns ", c.PrettyPrint(r.GetWallets()))
	}
	return nil, r.GetWallets()
}

func (k Keeper) EnclaveSyncCredentials(sdkctx sdk.Context) (error, []*types.Credential) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SyncCredentials(ctx, &types.MsgSyncCredentials{Clear: true})
	if err != nil {
		c.ContextError(sdkctx, "error returned by SyncCredentials on enclave "+err.Error())
		return err, nil
	}
	if len(r.GetCredentials()) > 0 {
		c.ContextDebug(sdkctx, "SyncCredentials returns", r.GetCredentials())
	}
	return nil, r.GetCredentials()
}

func (k Keeper) EnclaveSyncRecoverKeys(sdkctx sdk.Context) (error, []*types.RecoverKey) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SyncRecoverKeys(ctx, &types.MsgSyncRecoverKeys{Clear: true})
	if err != nil {
		c.ContextError(sdkctx, "error returned by SyncRecoverKeys on enclave "+err.Error())
		return err, nil
	}
	if len(r.GetRecoverKeys()) > 0 {
		c.ContextDebug(sdkctx, "SyncRecoverKeys returns", r.GetRecoverKeys())
	}
	return nil, r.GetRecoverKeys()
}

func (k Keeper) EnclaveSyncSuspiciousTransactions(sdkctx sdk.Context) (error, []*types.SuspiciousTransaction) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.SyncSuspiciousTransactions(ctx, &types.MsgSyncSuspiciousTransactions{Clear: true})
	if err != nil {
		c.ContextError(sdkctx, "error returned by SyncSuspiciousTransactions on enclave "+err.Error())
		return err, nil
	}
	if len(r.GetSuspiciousTransactions()) > 0 {
		c.ContextDebug(sdkctx, "SyncSuspiciousTransactions returns", r.GetSuspiciousTransactions())
	}
	return nil, r.GetSuspiciousTransactions()
}

func (k Keeper) EnclaveValidateDestinationWallet(sdkctx sdk.Context, msg *types.MsgCreateWallet) (int, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateDestinationWallet not called in checktx")
		return types.WalletTypeCheckTx, nil
	}

	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateCredential(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateCredential on enclave "+err.Error())
		return false, err
	}
	return r.Status, nil
}

func (k Keeper) EnclaveValidateTransferPrime(sdkctx sdk.Context, msg *types.MsgTransferFunds) (bool, error) {
	if sdkctx.IsCheckTx() {
		c.ContextDebug(sdkctx, "ValidateTransferPrime not called in checktx")
		return true, nil
	}

	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	stx := &types.MsgScanTransactions{
		Timestamp:    currentBlockHeader.Time,
		Height:       currentBlockHeader.Height,
		Msg:          msg,
		Exchangerate: conversion.String(),
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

	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.ValidateTransferDoublePrime(grpcctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by ValidateTransferDoublePrime on enclave "+err.Error())
		return false, err
	}
	return r.UpdateDestinationWallet, nil
}

func (k Keeper) EnclaveQuerySyncEnclave(sdkctx sdk.Context, msg *types.QueryEnclaveSyncEnclaveRequest) (error, *types.QueryEnclaveSyncEnclaveResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveSyncEnclave(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQuerySyncEnclave on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryValidateEnclaveIdentity(sdkctx sdk.Context, msg *types.QueryEnclaveValidateEnclaveIdentityRequest) (error, *types.QueryEnclaveValidateEnclaveIdentityResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveValidateEnclaveIdentity(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQueryValidateEnclaveIdentity on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryFindCredential(sdkctx sdk.Context, msg *types.QueryFindCredentialRequest) (error, *types.QueryFindCredentialResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.QueryFindCredential(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryFindCredential on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQuerySecretShare(sdkctx sdk.Context, msg *types.QueryEnclaveSecretShareRequest) (error, *types.QueryEnclaveSecretShareResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveSecretShare(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by EnclaveQuerySecretShare on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryRecoverKeyShare(sdkctx sdk.Context, msg *types.QueryEnclaveRecoverKeyShareRequest) (error, *types.QueryEnclaveRecoverKeyShareResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	r, err := EnclaveGRPCClient.QueryEnclaveRecoverKeyShare(ctx, msg)
	if err != nil {
		c.ContextError(sdkctx, "error returned by QueryRecoverKeyShare on enclave "+err.Error())
		return err, nil
	}

	return nil, r
}

func (k Keeper) EnclaveQueryGetRecoverKey(sdkctx sdk.Context, msg *types.QueryGetRecoverKeyRequest) (error, *types.QueryGetRecoverKeyResponse) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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
	grpcctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
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

func (k Keeper) displayStoresSync(sdkctx sdk.Context) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	gsh := &types.MsgGetStoreHash{}

	storeHashes, err := EnclaveGRPCClient.GetStoreHash(ctx, gsh)
	if err != nil {
		c.ContextDebug(sdkctx, "error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	for _, sh := range storeHashes.GetHashes() {
		h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
		if sh.Hash != h {
			c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
		} else {
			c.ContextDebug(sdkctx, "in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
		}
	}

	return nil
}

// sync DB between chain and enclave
func (k Keeper) EnclaveSynchronizeStores(sdkctx sdk.Context) error {
	c.ContextDebug(sdkctx, "Qadena module BeginBlock -- Chain initialized and ready for business, synchronizing enclave...")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.DebugTimeout)*time.Second)
	defer cancel()

	gsh := &types.MsgGetStoreHash{}

	storeHashes, err := EnclaveGRPCClient.GetStoreHash(ctx, gsh)
	if err != nil {
		c.ContextDebug(sdkctx, "error returned by GetStoreHash on enclave "+err.Error())
		return err
	}

	checkSync := false

	for _, sh := range storeHashes.GetHashes() {
		h := c.StoreHashByKVStoreService(sdkctx, k.storeService, sh.Key)
		if sh.Hash != h {
			switch sh.Key {
			case types.WalletKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				wallets := k.GetAllWallet(sdkctx)
				//    fmt.Println("wallets", list)
				for _, wallet := range wallets {
					k.EnclaveClientSetWallet(sdkctx, wallet)
					checkSync = true
				}
			case types.CredentialKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				credentials := k.GetAllCredential(sdkctx)
				for _, credential := range credentials {
					k.EnclaveClientSetCredential(sdkctx, credential)
					checkSync = true
				}
			case types.PublicKeyKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				publicKeys := k.GetAllPublicKey(sdkctx)
				c.ContextDebug(sdkctx, "synchronizing PublicKeys", publicKeys)
				for _, publicKey := range publicKeys {
					k.EnclaveClientSetPublicKey(sdkctx, publicKey)
					checkSync = true
				}
			case types.JarRegulatorKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				jarRegulators := k.GetAllJarRegulator(sdkctx)
				for _, jarRegulator := range jarRegulators {
					k.EnclaveClientSetJarRegulator(sdkctx, jarRegulator)
					checkSync = true
				}
			case types.IntervalPublicKeyIDKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				intervalPublicKeyIDs := k.GetAllIntervalPublicKeyID(sdkctx)
				for _, intervalPublicKeyID := range intervalPublicKeyIDs {
					k.EnclaveClientSetIntervalPublicKeyId(sdkctx, intervalPublicKeyID)
					checkSync = true
				}
			case types.ProtectKeyKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				protectKeys := k.GetAllProtectKey(sdkctx)
				for _, protectKey := range protectKeys {
					k.EnclaveClientSetProtectKey(sdkctx, protectKey)
					checkSync = true
				}
			case types.RecoverKeyKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				recoverKeys := k.GetAllRecoverKey(sdkctx)
				for _, recoverKey := range recoverKeys {
					k.EnclaveClientSetRecoverKey(sdkctx, recoverKey)
					checkSync = true
				}
			case types.EnclaveIdentityKeyPrefix:
				c.ContextError(sdkctx, "OUT-OF-SYNC store:  key="+sh.Key+" enclave-hash="+c.DisplayHash(sh.Hash)+" chain-hash="+c.DisplayHash(h))
				enclaveIdentities := k.GetAllEnclaveIdentity(sdkctx)
				for _, enclaveIdentity := range enclaveIdentities {
					k.EnclaveClientSetEnclaveIdentity(sdkctx, enclaveIdentity)
					checkSync = true
				}
			default:
				c.ContextDebug(sdkctx, "Ignoring key="+sh.Key+" in Qadena module")
			}

		} else {
			c.ContextDebug(sdkctx, "in-sync store:  key="+sh.Key+" hash="+c.DisplayHash(h))
		}
	}

	if checkSync {
		c.ContextDebug(sdkctx, "Checking Sync after chain->enclave synchronization")
		k.displayStoresSync(sdkctx)
	}

	return nil
}

func (k Keeper) EnclaveEndBlock(sdkctx sdk.Context) {
	//  fmt.Println("qadena module EndBlock")
	err, changedWallets := k.EnclaveSyncWallets(sdkctx)
	checkSync := false

	if err != nil {
		c.ContextError(sdkctx, err.Error())
	}

	for _, wallet := range changedWallets {
		k.SetWalletNoEnclave(sdkctx, *wallet)
		checkSync = true
	}

	err, changedCredentials := k.EnclaveSyncCredentials(sdkctx)

	if err != nil {
		c.ContextError(sdkctx, err.Error())
	}

	for _, credential := range changedCredentials {
		k.SetCredentialNoEnclave(sdkctx, *credential)
		checkSync = true
	}

	err, changedRecoverKeys := k.EnclaveSyncRecoverKeys(sdkctx)

	if err != nil {
		c.ContextError(sdkctx, err.Error())
	}

	for _, recoverKey := range changedRecoverKeys {
		k.SetRecoverKey(sdkctx, *recoverKey)
		checkSync = true
	}

	err, newSuspiciousTransactions := k.EnclaveSyncSuspiciousTransactions(sdkctx)

	if err != nil {
		c.ContextError(sdkctx, err.Error())
	}

	for _, st := range newSuspiciousTransactions {
		k.AppendSuspiciousTransaction(sdkctx, *st)
		checkSync = true
	}

	if checkSync {
		c.ContextDebug(sdkctx, "Checking Sync after enclave->chain synchronization")
		k.displayStoresSync(sdkctx)
	}

	k.EnclaveInvokeEndBlock(sdkctx)
}
