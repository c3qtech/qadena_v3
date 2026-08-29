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
	if err != nil {
		if err != nil {
			c.ContextDebug(sdkctx, "clientVerifyRemoteReportRealEnclave: remote report tcbstatus "+tcbstatus.Explain(remoteReport.TCBStatus))
			if remoteReport.TCBStatus == tcbstatus.Revoked || remoteReport.TCBStatus == tcbstatus.OutOfDate {
				c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: error verifying remote report ", err)
				return false, "", ""
			} else {
				c.ContextError(sdkctx, "clientVerifyRemoteReportRealEnclave: neither revoked nor completely out-of-date")
			}
		}
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
