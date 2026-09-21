//go:build realenclave
// +build realenclave

// this only gets built on Linux/SGX

package main

import (
	"bytes"
	//	"encoding/binary"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	//	"fmt"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/eclient"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/keeper"

	"cosmossdk.io/log"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// CLONE ALERT:  THIS IS MOSTLY A CLONE OF jar_realenclave.go

var VerifyReportSignerID []byte
var VerifyReportUniqueID []byte

func verifyReport(report attestation.Report) error {
	if !bytes.Equal(report.SignerID, VerifyReportSignerID) {
		return errors.New("invalid signer")
	}

	return nil
}

func dialRealEnclave(logger log.Logger, addr string, signerID string, uniqueID string) (*grpc.ClientConn, error) {
	c.LoggerDebug(logger, "dialRealEnclave", addr, signerID, uniqueID)

	// get signerID command line argument
	var err error
	VerifyReportSignerID, err = hex.DecodeString(signerID)
	if err != nil {
		return nil, err
	}

	if len(VerifyReportSignerID) == 0 {
		return nil, errors.New("signerID missing")
	}

	VerifyReportUniqueID, err = hex.DecodeString(uniqueID)
	if err != nil {
		return nil, err
	}

	if len(VerifyReportUniqueID) == 0 {
		return nil, errors.New("uniqueID missing")
	}

	// Create a TLS config that verifies a certificate with embedded report.
	tlsConfig := eclient.CreateAttestationClientTLSConfig(verifyReport)

	c.LoggerDebug(logger, "tlsConfig", tlsConfig)

	// Set up a connection to the server.
	//
	// EVERY DIAL TO THE ENCLAVE MUST CARRY EnclaveInFlightInterceptor, this one included -- it is
	// the REAL SGX path, so a node in production without it is the one case that matters.  The
	// interceptor is what lets the watchdog say whether calls were in flight when the enclave
	// died, which is the difference between reporting a wedge and reporting an idle node.  Missing
	// it here would reproduce exactly the opt-in fragility the transport close exists to fix: a
	// single dial site that skipped the invariant, invisible until the incident.
	cred := credentials.NewTLS(tlsConfig)
	conn, err := grpc.Dial(addr,
		grpc.WithTransportCredentials(cred),
		grpc.WithChainUnaryInterceptor(keeper.EnclaveInFlightInterceptor))

	return conn, err
}

// returns true if valid
func clientVerifyRemoteReportRealEnclave(sdkctx sdk.Context, remoteReportBytes []byte, certifyData string) (success bool, signerID string, uniqueID string) {
	remoteReport, err := eclient.VerifyRemoteReport(remoteReportBytes)

	// A FAILED VERIFICATION MUST NOT REACH THE REPORT'S CONTENTS.  The enclave-side verifier states
	// this at length (cmd/qadenad_enclave/enclave.go, verifyRemoteReport); this copy had been left
	// with the shape that was fixed there, and the checks below make that shape unsafe rather than
	// merely wrong:
	//
	//   ego returns a ZERO Report for any error that is not ErrTCBLevelInvalid, and a zero Report
	//   reads as TCBStatus UpToDate, Debug FALSE and nil Data -- it looks like a healthy PRODUCTION
	//   report.  Falling through meant a forged report reached Data[:32], panicked on nil, and was
	//   rejected by the gRPC recovery interceptor BY ACCIDENT rather than by any check.
	//
	//   tcbstatus.OutOfDateConfigurationNeeded is 4 while OutOfDate is 1, so an authentic report
	//   from a genuinely out-of-date platform slipped past the two != comparisons and was accepted.
	//
	// So: reject on any error that is not the TCB-level signal, then judge the status against the
	// explicit ALLOW-list in c.AcceptableTCBStatus -- shared with the enclave-side verifier so the
	// two cannot diverge into a trust asymmetry.  Read the commentary there before changing it:
	// OutOfDateConfigurationNeeded is currently admitted, deliberately, and that is not free.
	if err != nil && !errors.Is(err, attestation.ErrTCBLevelInvalid) {
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: remote report did not verify: "+err.Error())
		return false, "", ""
	}
	c.ContextDebug(sdkctx, "clientVerifyRemoteReportRealEnclave: remote report tcbstatus "+tcbstatus.Explain(remoteReport.TCBStatus))
	if !c.AcceptableTCBStatus(remoteReport.TCBStatus) {
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: refusing remote report with TCB status "+
			tcbstatus.Explain(remoteReport.TCBStatus))
		return false, "", ""
	}

	// A DEBUG-MODE ENCLAVE IS MEASURED BUT NOT CONFIDENTIAL.  SGX debug mode leaves EDBGRD/EDBGWR
	// open, so the host can read and write enclave memory at will: the quote still proves WHICH
	// code ran, and proves nothing about anything that code tried to keep secret.  Every private
	// key this chain protects would be readable by whoever runs the node.
	//
	// The flag comes from enclave.json's "debug" at `ego sign` time and rides in the quote, so this
	// is the check that makes that setting load-bearing rather than advisory.  It must come AFTER
	// the verification gate above: on a zero Report this field reads false, which is exactly the
	// answer an attacker wants.
	if remoteReport.Debug {
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: refusing a DEBUG-mode enclave report -- "+
			"its memory is readable by the host, so the measurement says nothing about confidentiality")
		return false, "", ""
	}

	hash := sha256.Sum256([]byte(certifyData))
	if bytes.Compare(remoteReport.Data[:len(hash)], hash[:]) != 0 {
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: mismatch hash")
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: remoteReportData hash", hex.EncodeToString(remoteReport.Data[:len(hash)]))
		c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: certifyData hash", hex.EncodeToString(hash[:]))
		return false, "", ""
	}
	c.ContextDebug(sdkctx, "clientVerifyRemoteReportRealEnclave: hash match")

	// NOTE:  THIS DOES NOT HAVE TO CHECK IF THE UNIQUEID IS OK, SINCE THAT'S ALREADY DONE IN EnclaveClientVerifyRemoteReport

	return true, hex.EncodeToString(remoteReport.SignerID), hex.EncodeToString(remoteReport.UniqueID)
}

func init() {
	keeper.EnclaveDialEnclave = dialRealEnclave
	keeper.EnclaveClientVerifyRemoteReport = clientVerifyRemoteReportRealEnclave
}
