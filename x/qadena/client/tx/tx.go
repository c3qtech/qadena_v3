package tx

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	gogogrpc "github.com/cosmos/gogoproto/grpc"
	"github.com/spf13/pflag"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/input"
	cryptotypes "github.com/cosmos/cosmos-sdk/crypto/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrors "github.com/cosmos/cosmos-sdk/types/errors"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	authsigning "github.com/cosmos/cosmos-sdk/x/auth/signing"

	sdktypeserrors "github.com/cosmos/cosmos-sdk/types/errors"

	// needed by CheckTxByHash

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"

	abciv1beta1 "cosmossdk.io/api/cosmos/base/abci/v1beta1"
	txtypes "cosmossdk.io/api/cosmos/tx/v1beta1"
	"github.com/cosmos/cosmos-sdk/client/flags"
)

// QueryTxByHashGRPC queries for a single transaction by hash using gRPC instead of CometBFT RPC.
// This is a replacement for authtx.QueryTx that uses the Cosmos SDK gRPC service.
func QueryTxByHashGRPC(clientCtx client.Context, hashHexStr string) (*abciv1beta1.TxResponse, error) {
	// Create the tx service client
	fmt.Printf("%v | QueryTxByHashGRPC %s\n", time.Now().Format("2006-01-02 15:04:05"), hashHexStr)
	txServiceClient := txtypes.NewServiceClient(clientCtx)

	// Query the transaction using gRPC
	grpcRes, err := txServiceClient.GetTx(context.Background(), &txtypes.GetTxRequest{
		Hash: hashHexStr,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query tx via gRPC: %w", err)
	}

	// Convert the gRPC response to TxResponse
	// The grpcRes.TxResponse is already a *sdk.TxResponse
	if grpcRes.TxResponse == nil {
		return nil, fmt.Errorf("tx response is nil for hash %s", hashHexStr)
	}

	return grpcRes.TxResponse, nil
}

func CheckTxByHash(ctx client.Context, txHash string) (err error, success bool) {
	for tryCount := 8; tryCount > 0; tryCount-- {
		hasError := false

		/*
			clientCtx, err := client.GetClientQueryContext(cmd)
			if err != nil {
				// this is a bad error, so return immediately
				hasError = true
				return err, false
			}
		*/

		// if hash is given, then query the tx by hash
		fmt.Printf("%v | Querying tx %s\n", time.Now().Format("2006-01-02 15:04:05"), txHash)
		//output, err := authtx.QueryTx(ctx, txHash)
		output, err := QueryTxByHashGRPC(ctx, txHash)
		if err != nil {
			hasError = true
			if tryCount == 0 {
				fmt.Printf("%v | error querying tx %s\n", time.Now().Format("2006-01-02 15:04:05"), err)
				return err, false
			}
		}

		if output == nil /*|| output.Empty()*/ {
			fmt.Printf("%v | tx not found %s\n", time.Now().Format("2006-01-02 15:04:05"), txHash)
			hasError = true
			if tryCount == 0 {
				fmt.Printf("%v | tx not found (output empty) %s\n", time.Now().Format("2006-01-02 15:04:05"), txHash)
				return fmt.Errorf("no transaction found with hash %s", txHash), false
			}
		} else if output.Code != 0 {
			hasError = true
			fmt.Printf("%v | tx failed %s %d %s\n", time.Now().Format("2006-01-02 15:04:05"), txHash, output.Code, output.RawLog)
			return fmt.Errorf("tx %s failed with %d: %s", txHash, output.Code, output.RawLog), false
		}

		if !hasError {
			break
		} else {
			// sleep a few milliseconds
			time.Sleep(750 * time.Millisecond)
		}
	}

	return nil, true
}

func CheckTxCLIResponse(clientCtx client.Context, err error, res *sdk.TxResponse, oper string) (error, bool) {
	if err != nil {
		st := status.Convert(err)
		// if st.Code() == codes.Unauthenticated  & & st.Message contains "sequence mismatch"
		if st.Code() == codes.Unknown && strings.Contains(st.Message(), "sequence mismatch") {
			fmt.Printf("%v | got sequence mismatch, retrying...\n", time.Now().Format("2006-01-02 15:04:05"))
			return err, true
		}
		return err, false
	}

	// check if successful
	if res.Code != 0 {
		if res.Codespace == "sdk" && (res.Code == sdktypeserrors.ErrWrongSequence.ABCICode() || res.Code == sdktypeserrors.ErrTxInMempoolCache.ABCICode()) {
			return fmt.Errorf("failed to "+oper+": %s, but should retry", res.RawLog), true // should retry
		}

		return fmt.Errorf("failed to "+oper+": %s", res.RawLog), false
	}

	// call CheckTxByHash
	err, success := CheckTxByHash(clientCtx, res.TxHash)

	if err != nil {
		return err, false
	}

	if !success {
		return fmt.Errorf("failed to "+oper+": %s", res.RawLog), false
	}

	if c.Debug && c.DebugFull {
		fmt.Printf("%v | success: %s\n", time.Now().Format("2006-01-02 15:04:05"), res.TxHash)
	}

	return nil, false
}

// returns true if the sequence changed by more than 1 (meaning there many simultaneous transactions from this wallet), false otherwise; also returns true if we didn't detect a change
func waitForSequenceChange(clientCtx client.Context, flagSet *pflag.FlagSet, oldSequence uint64) bool {
	fmt.Printf("%v | waiting for sequence change from %d\n", time.Now().Format("2006-01-02 15:04:05"), oldSequence)
	for i := 0; i < 15; i++ {
		factory, err := NewFactoryCLI(clientCtx, flagSet)
		if err != nil {
			panic(err)
		}
		factory, err = factory.Prepare(clientCtx)
		if err != nil {
			panic(err)
		}
		if factory.Sequence() > oldSequence {
			fmt.Printf("%v | sequence changed from %d to %d\n", time.Now().Format("2006-01-02 15:04:05"), oldSequence, factory.Sequence())
			if factory.Sequence() > oldSequence+1 {
				return true
			} else {
				return false
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return true
}

func GenerateOrBroadcastTxCLISync(clientCtx client.Context, flagSet *pflag.FlagSet, op string, msgs ...sdk.Msg) (error, *sdk.TxResponse) {
	// array of timeouts, exponentially increasing
	normalTimeouts := []time.Duration{
		1 * time.Second,
		1 * time.Second,
		2 * time.Second,
		2 * time.Second,
		4 * time.Second,
		4 * time.Second,
		4 * time.Second,
		4 * time.Second,
		10 * time.Second,
		10 * time.Second,
		10 * time.Second,
	}

	backoffTimeouts := []time.Duration{
		20 * time.Second,
		20 * time.Second,
		20 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
		30 * time.Second,
	}

	timeouts := normalTimeouts

	gasPrice, err := flagSet.GetString(flags.FlagGasPrices)
	if err != nil {
		fmt.Printf("%v | got error %s\n", time.Now().Format("2006-01-02 15:04:05"), err)
		return err, nil
	}
	fmt.Printf("%v | flags.FlagGasPrices %s\n", time.Now().Format("2006-01-02 15:04:05"), gasPrice)
	if gasPrice == "" {
		flagSet.Set(flags.FlagGasPrices, "500000000aqdn")
	}

	flagSet.Set(flags.FlagGas, "auto")
	//flagSet.Set(flags.FlagGas, "100000000000")
	flagSet.Set(flags.FlagGasAdjustment, "1.2")

	txf, err := NewFactoryCLI(clientCtx, flagSet)
	if err != nil {
		return err, nil
	}

	shouldRetry := true
	backoff := false

	var res *sdk.TxResponse
	maxTries := 0
	for {
		txf, err = txf.Prepare(clientCtx)
		if err != nil {
			return err, nil
		}

		oldSequence := txf.Sequence()
		// fmt.Printf("%v | will use sequence %d for %s\n", time.Now().Format("2006-01-02 15:04:05"), oldSequence, txf.fromName)

		/* ADD THIS IF YOU WANT TO TEST SEQUENCE ERROR
		fmt.Println("HACK")
		txf = txf.WithSequence(oldSequence - 1)
		*/

		fmt.Printf("%v | GenerateOrBroadcastTxCLISync\n", time.Now().Format("2006-01-02 15:04:05"))
		err, res = GenerateOrBroadcastTxWithFactory(clientCtx, txf, msgs...)

		fmt.Printf("%v | CheckTxCLIResponse\n", time.Now().Format("2006-01-02 15:04:05"))
		err, shouldRetry = CheckTxCLIResponse(clientCtx, err, res, op)
		if shouldRetry {
			// delay for a bit
			time.Sleep(timeouts[maxTries])
			// wait for the sequence to change
			newBackoff := waitForSequenceChange(clientCtx, flagSet, oldSequence)
			txf, err = NewFactoryCLI(clientCtx, flagSet)
			if err != nil {
				return err, nil
			}
			if newBackoff && !backoff {
				maxTries = 0
				backoff = true
				fmt.Printf("%v | backing off\n", time.Now().Format("2006-01-02 15:04:05"))
				timeouts = backoffTimeouts
			} else {
				maxTries++
				if maxTries == len(timeouts) {
					fmt.Printf("%v | max retries exceeded\n", time.Now().Format("2006-01-02 15:04:05"))
					return errors.New("max retries exceeded"), nil
				}
			}
			continue
		} else if err != nil {
			return err, nil
		} else {
			break
		}
	}

	oldSequence := txf.Sequence()
	fmt.Printf("%v | used sequence %d\n", time.Now().Format("2006-01-02 15:04:05"), oldSequence)
	waitForSequenceChange(clientCtx, flagSet, oldSequence)

	// note: we get here even if the sequence number did not increase, but the chain may just be delayed in updating the sequence number
	return nil, res
}

// GenerateOrBroadcastTxWithFactory will either generate and print an unsigned transaction
// or sign it and broadcast it returning an error upon failure.
func GenerateOrBroadcastTxWithFactory(clientCtx client.Context, txf Factory, msgs ...sdk.Msg) (error, *sdk.TxResponse) {
	// Validate all msgs before generating or broadcasting the tx.
	// We were calling ValidateBasic separately in each CLI handler before.
	// Right now, we're factorizing that call inside this function.
	// ref: https://github.com/cosmos/cosmos-sdk/pull/9236#discussion_r623803504
	for _, msg := range msgs {
		m, ok := msg.(sdk.HasValidateBasic)
		if !ok {
			continue
		}

		if err := m.ValidateBasic(); err != nil {
			return err, nil
		}
	}

	// If the --aux flag is set, we simply generate and print the AuxSignerData.
	if clientCtx.IsAux {
		auxSignerData, err := makeAuxSignerData(clientCtx, txf, msgs...)
		if err != nil {
			return err, nil
		}

		return clientCtx.PrintProto(&auxSignerData), nil
	}

	if clientCtx.GenerateOnly {
		return txf.PrintUnsignedTx(clientCtx, msgs...), nil
	}

	return BroadcastTx(clientCtx, txf, msgs...)
}

// BroadcastTx attempts to generate, sign and broadcast a transaction with the
// given set of messages. It will also simulate gas requirements if necessary.
// It will return an error upon failure.
func BroadcastTx(clientCtx client.Context, txf Factory, msgs ...sdk.Msg) (error, *sdk.TxResponse) {
	if txf.SimulateAndExecute() || clientCtx.Simulate {
		if clientCtx.Offline {
			return errors.New("cannot estimate gas in offline mode"), nil
		}

		_, adjusted, err := CalculateGas(clientCtx, txf, msgs...)
		if err != nil {
			return err, nil
		}

		txf = txf.WithGas(adjusted)
		//_, _ = fmt.Fprintf(os.Stderr, "%s\n", GasEstimateResponse{GasEstimate: txf.Gas()})
	}

	if clientCtx.Simulate {
		return nil, nil
	}

	tx, err := txf.BuildUnsignedTx(msgs...)
	if err != nil {
		return err, nil
	}

	if !clientCtx.SkipConfirm {
		encoder := txf.txConfig.TxJSONEncoder()
		if encoder == nil {
			return errors.New("failed to encode transaction: tx json encoder is nil"), nil
		}

		txBytes, err := encoder(tx.GetTx())
		if err != nil {
			return fmt.Errorf("failed to encode transaction: %w", err), nil
		}

		if err := clientCtx.PrintRaw(json.RawMessage(txBytes)); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n%s\n", err, txBytes)
		}

		buf := bufio.NewReader(os.Stdin)
		ok, err := input.GetConfirmation("confirm transaction before signing and broadcasting", buf, os.Stderr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\ncanceled transaction\n", err)
			return err, nil
		}
		if !ok {
			_, _ = fmt.Fprintln(os.Stderr, "canceled transaction")
			return nil, nil
		}
	}

	if err = Sign(clientCtx.CmdContext, txf, clientCtx.FromName, tx, true); err != nil {
		return err, nil
	}

	txBytes, err := clientCtx.TxConfig.TxEncoder()(tx.GetTx())
	if err != nil {
		return err, nil
	}

	// broadcast to a CometBFT node
	res, err := clientCtx.BroadcastTx(txBytes)
	if err != nil {
		return err, nil
	}

	return clientCtx.PrintProto(res), res
}

// CalculateGas simulates the execution of a transaction and returns the
// simulation response obtained by the query and the adjusted gas amount.
func CalculateGas(
	clientCtx gogogrpc.ClientConn, txf Factory, msgs ...sdk.Msg,
) (*tx.SimulateResponse, uint64, error) {
	txBytes, err := txf.BuildSimTx(msgs...)
	if err != nil {
		return nil, 0, err
	}

	txSvcClient := tx.NewServiceClient(clientCtx)
	simRes, err := txSvcClient.Simulate(context.Background(), &tx.SimulateRequest{
		TxBytes: txBytes,
	})
	if err != nil {
		return nil, 0, err
	}

	return simRes, uint64(txf.GasAdjustment() * float64(simRes.GasInfo.GasUsed)), nil
}

// SignWithPrivKey signs a given tx with the given private key, and returns the
// corresponding SignatureV2 if the signing is successful.
func SignWithPrivKey(
	ctx context.Context,
	signMode signing.SignMode, signerData authsigning.SignerData,
	txBuilder client.TxBuilder, priv cryptotypes.PrivKey, txConfig client.TxConfig,
	accSeq uint64,
) (signing.SignatureV2, error) {
	var sigV2 signing.SignatureV2

	// Generate the bytes to be signed.
	signBytes, err := authsigning.GetSignBytesAdapter(
		ctx, txConfig.SignModeHandler(), signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return sigV2, err
	}

	// Sign those bytes
	signature, err := priv.Sign(signBytes)
	if err != nil {
		return sigV2, err
	}

	// Construct the SignatureV2 struct
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: signature,
	}

	sigV2 = signing.SignatureV2{
		PubKey:   priv.PubKey(),
		Data:     &sigData,
		Sequence: accSeq,
	}

	return sigV2, nil
}

// countDirectSigners counts the number of DIRECT signers in a signature data.
func countDirectSigners(data signing.SignatureData) int {
	switch data := data.(type) {
	case *signing.SingleSignatureData:
		if data.SignMode == signing.SignMode_SIGN_MODE_DIRECT {
			return 1
		}

		return 0
	case *signing.MultiSignatureData:
		directSigners := 0
		for _, d := range data.Signatures {
			directSigners += countDirectSigners(d)
		}

		return directSigners
	default:
		panic("unreachable case")
	}
}

// checkMultipleSigners checks that there can be maximum one DIRECT signer in
// a tx.
func checkMultipleSigners(tx authsigning.Tx) error {
	directSigners := 0
	sigsV2, err := tx.GetSignaturesV2()
	if err != nil {
		return err
	}
	for _, sig := range sigsV2 {
		directSigners += countDirectSigners(sig.Data)
		if directSigners > 1 {
			return sdkerrors.ErrNotSupported.Wrap("txs signed with CLI can have maximum 1 DIRECT signer")
		}
	}

	return nil
}

// Sign signs a given tx with a named key. The bytes signed over are canconical.
// The resulting signature will be added to the transaction builder overwriting the previous
// ones if overwrite=true (otherwise, the signature will be appended).
// Signing a transaction with mutltiple signers in the DIRECT mode is not supprted and will
// return an error.
// An error is returned upon failure.
func Sign(ctx context.Context, txf Factory, name string, txBuilder client.TxBuilder, overwriteSig bool) error {
	if txf.keybase == nil {
		return errors.New("keybase must be set prior to signing a transaction")
	}

	var err error
	signMode := txf.signMode
	if signMode == signing.SignMode_SIGN_MODE_UNSPECIFIED {
		// use the SignModeHandler's default mode if unspecified
		signMode, err = authsigning.APISignModeToInternal(txf.txConfig.SignModeHandler().DefaultMode())
		if err != nil {
			return err
		}
	}

	k, err := txf.keybase.Key(name)
	if err != nil {
		return err
	}

	pubKey, err := k.GetPubKey()
	if err != nil {
		return err
	}

	signerData := authsigning.SignerData{
		ChainID:       txf.chainID,
		AccountNumber: txf.accountNumber,
		Sequence:      txf.sequence,
		PubKey:        pubKey,
		Address:       sdk.AccAddress(pubKey.Address()).String(),
	}

	// For SIGN_MODE_DIRECT, calling SetSignatures calls setSignerInfos on
	// TxBuilder under the hood, and SignerInfos is needed to generated the
	// sign bytes. This is the reason for setting SetSignatures here, with a
	// nil signature.
	//
	// Note: this line is not needed for SIGN_MODE_LEGACY_AMINO, but putting it
	// also doesn't affect its generated sign bytes, so for code's simplicity
	// sake, we put it here.
	sigData := signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: nil,
	}
	sig := signing.SignatureV2{
		PubKey:   pubKey,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	var prevSignatures []signing.SignatureV2
	if !overwriteSig {
		prevSignatures, err = txBuilder.GetTx().GetSignaturesV2()
		if err != nil {
			return err
		}
	}
	// Overwrite or append signer infos.
	var sigs []signing.SignatureV2
	if overwriteSig {
		sigs = []signing.SignatureV2{sig}
	} else {
		sigs = append(sigs, prevSignatures...)
		sigs = append(sigs, sig)
	}
	if err := txBuilder.SetSignatures(sigs...); err != nil {
		return err
	}

	if err := checkMultipleSigners(txBuilder.GetTx()); err != nil {
		return err
	}

	bytesToSign, err := authsigning.GetSignBytesAdapter(ctx, txf.txConfig.SignModeHandler(), signMode, signerData, txBuilder.GetTx())
	if err != nil {
		return err
	}

	// Sign those bytes
	sigBytes, _, err := txf.keybase.Sign(name, bytesToSign, signMode)
	if err != nil {
		return err
	}

	// Construct the SignatureV2 struct
	sigData = signing.SingleSignatureData{
		SignMode:  signMode,
		Signature: sigBytes,
	}
	sig = signing.SignatureV2{
		PubKey:   pubKey,
		Data:     &sigData,
		Sequence: txf.Sequence(),
	}

	if overwriteSig {
		err = txBuilder.SetSignatures(sig)
	} else {
		prevSignatures = append(prevSignatures, sig)
		err = txBuilder.SetSignatures(prevSignatures...)
	}

	if err != nil {
		return fmt.Errorf("unable to set signatures on payload: %w", err)
	}

	// Run optional preprocessing if specified. By default, this is unset
	// and will return nil.
	return txf.PreprocessTx(name, txBuilder)
}

// GasEstimateResponse defines a response definition for tx gas estimation.
type GasEstimateResponse struct {
	GasEstimate uint64 `json:"gas_estimate" yaml:"gas_estimate"`
}

func (gr GasEstimateResponse) String() string {
	return fmt.Sprintf("gas estimate: %d", gr.GasEstimate)
}

// makeAuxSignerData generates an AuxSignerData from the client inputs.
func makeAuxSignerData(clientCtx client.Context, f Factory, msgs ...sdk.Msg) (tx.AuxSignerData, error) {
	b := NewAuxTxBuilder()
	fromAddress, name, _, err := client.GetFromFields(clientCtx, clientCtx.Keyring, clientCtx.From)
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	b.SetAddress(fromAddress.String())
	if clientCtx.Offline {
		b.SetAccountNumber(f.accountNumber)
		b.SetSequence(f.sequence)
	} else {
		accNum, seq, err := clientCtx.AccountRetriever.GetAccountNumberSequence(clientCtx, fromAddress)
		if err != nil {
			return tx.AuxSignerData{}, err
		}
		b.SetAccountNumber(accNum)
		b.SetSequence(seq)
	}

	err = b.SetMsgs(msgs...)
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	err = b.SetSignMode(f.SignMode())
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	key, err := clientCtx.Keyring.Key(name)
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	pub, err := key.GetPubKey()
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	err = b.SetPubKey(pub)
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	b.SetChainID(clientCtx.ChainID)
	signBz, err := b.GetSignBytes()
	if err != nil {
		return tx.AuxSignerData{}, err
	}

	sig, _, err := clientCtx.Keyring.Sign(name, signBz, f.signMode)
	if err != nil {
		return tx.AuxSignerData{}, err
	}
	b.SetSignature(sig)

	return b.GetAuxSignerData()
}
