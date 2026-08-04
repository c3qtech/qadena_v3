package main

// The identity provider's half of the credential correction flow.
//
// Structurally this issues nothing new: it publishes four ownerless credentials under a fresh claim
// code, exactly as a first-time KYC does.  What it adds is (a) a pre-check with the very same
// policy engine the enclave runs, so the user learns a correction will be refused before spending a
// transaction on it, and (b) referenceCredentialID pointing at the credential being superseded, so
// the lineage and the reuse royalty stay intact.
//
// It deliberately never learns the user's post-claim credentialID or wallet: the corrected data is
// published ownerless and the user folds it in themselves with MsgUpdateCredential.
//
// Personal info only.  This server has never issued phone or email credentials -- those come from an
// identity provider running `tx qadena create-credential <a> <bf> phone-contact-info <value>` -- so a
// corrected contact goes out the same way, with a fresh claim code, and needs nothing here.

import (
	"encoding/hex"
	"errors"
	"math/big"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	sdk "github.com/cosmos/cosmos-sdk/types"

	c "github.com/c3qtech/qadena_v3/x/qadena/common"
	"github.com/c3qtech/qadena_v3/x/qadena/types"
)

type SubmitCorrectionKYCRequest struct {
	// from authenticate-otp, i.e. the subject has already been authenticated against the KYC on
	// file.  Its PersonalInfoDetails are the "before" side of the diff.
	SessionID string `json:"session-id"`
	// the user's fresh out-of-band claim code, compressed find-credential commitment
	UserFindCredentialPedersenCommmit string `json:"user-find-credential-pedersen-commit"`
	// the ownerless credentialID this correction supersedes, for lineage and royalties
	CorrectionOf string `json:"correction-of"`
	// whatever the provider records as justification (certificate number, case reference).  A
	// correction without one should not be issued, so this is required.
	SupportingDocument string `json:"supporting-document"`

	PIN string `json:"pin"`

	// The corrected values.  Any field left empty keeps what is on file, so a caller only has to
	// send what actually changed.
	FirstName   string `json:"first-name"`
	MiddleName  string `json:"middle-name"`
	LastName    string `json:"last-name"`
	Birthdate   string `json:"birthdate"`
	Citizenship string `json:"citizenship"`
	Residency   string `json:"residency"`
	Gender      string `json:"gender"`
}

type SubmitCorrectionKYCResponse struct {
	// how the policy engine classified the change, so a UI can say "correction" or "life event"
	Kind string `json:"kind"`
	// which identity fields moved, empty if only citizenship/residency did
	ChangedFields []string `json:"changed-fields"`
	// whether the user's identity hash will change, i.e. whether an alias will be recorded
	IdentityHashChanges bool `json:"identity-hash-changes"`
}

// orEmpty keeps the value on file when the caller did not send a replacement.
func orEmpty(replacement, onFile string) string {
	if replacement == "" {
		return onFile
	}
	return replacement
}

func (s *EKycServer) submitCorrectionKYC(context *gin.Context) {
	var request SubmitCorrectionKYCRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.LoggerDebug(logger, "submitCorrectionKYCRequest "+c.PrettyPrint(request))

	if request.SupportingDocument == "" {
		context.JSON(http.StatusBadRequest, gin.H{"error": "a correction needs a supporting document reference"})
		return
	}

	if request.CorrectionOf == "" {
		context.JSON(http.StatusBadRequest, gin.H{"error": "correction-of must name the credential being corrected"})
		return
	}

	if request.UserFindCredentialPedersenCommmit == "" {
		context.JSON(http.StatusBadRequest, gin.H{"error": "a correction needs a fresh claim code from the user"})
		return
	}

	sessionID, provider, err := s.decodeSubmittedKYCSession(request.SessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	onFile := sessionID.PersonalInfoDetails

	corrected, err := s.newPersonalInfo(request.PIN,
		orEmpty(request.FirstName, onFile.FirstName),
		orEmpty(request.MiddleName, onFile.MiddleName),
		orEmpty(request.LastName, onFile.LastName),
		orEmpty(request.Birthdate, onFile.Birthdate),
		orEmpty(request.Citizenship, onFile.Citizenship),
		orEmpty(request.Residency, onFile.Residency),
		orEmpty(request.Gender, onFile.Gender))
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// The same code the enclave will run, but against the COMPILED-IN defaults rather than the
	// chain's params, so neither direction is a guarantee.  The chain may be stricter (rate limits
	// need state this server cannot see) and, since the one-field rule became
	// update_credential_max_changed_identity_fields, it may also be more PERMISSIVE -- a chain that
	// raised the cap will accept a two-field correction this pre-check refuses.  Reading the live
	// params through UpdatePolicyFromParams is what closes that gap.
	verdict, err := c.ClassifyPersonalInfoUpdate(&onFile, corrected.Details, c.DefaultUpdatePolicy())
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.LoggerDebug(logger, "correction classified as "+verdict.Kind.String()+" fields "+strings.Join(verdict.ChangedFields, ","))

	compressed, err := hex.DecodeString(request.UserFindCredentialPedersenCommmit)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	userFindCredentialPC := c.UnprotoizeBPedersenCommit(&types.BPedersenCommit{C: &types.BECPoint{Compressed: compressed}})

	pin, ok := big.NewInt(0).SetString(corrected.PIN, 10)
	if !ok {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid pin"})
		return
	}

	msgs, err := s.createCorrectionCredentialMsgs(provider, userFindCredentialPC, corrected, request.CorrectionOf, pin)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !s.broadcastMsgs(provider, msgs) {
		context.JSON(http.StatusBadRequest, gin.H{"error": "could not create corrected credential"})
		return
	}

	context.JSON(http.StatusOK, SubmitCorrectionKYCResponse{
		Kind:                verdict.Kind.String(),
		ChangedFields:       verdict.ChangedFields,
		IdentityHashChanges: verdict.HashChanged,
	})
}

// createCorrectionCredentialMsgs builds the same four-message bundle a first-time KYC does.  All
// four must share one claim code and be issued together: MsgUpdateCredential's sub-updates look for
// the identity provider's corrected name sub-credentials under that same code.
func (s *EKycServer) createCorrectionCredentialMsgs(provider *Provider, userFindCredentialPC *c.PedersenCommit, corrected *types.EncryptablePersonalInfo, referenceCredentialID string, pin *big.Int) ([]sdk.Msg, error) {
	ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ClientCtx, types.SSNodeID, types.SSNodeType)
	if err != nil {
		return nil, err
	}

	msgs := make([]sdk.Msg, 0, 4)

	msg, err := s.createPersonalInfoCreateCredentialMsg(provider, userFindCredentialPC, corrected, referenceCredentialID, pin, ssIntervalPubKID, ssIntervalPubK)
	if err != nil {
		return nil, err
	}
	msgs = append(msgs, msg)

	for _, credentialType := range []string{
		types.FirstNamePersonalInfoCredentialType,
		types.MiddleNamePersonalInfoCredentialType,
		types.LastNamePersonalInfoCredentialType,
	} {
		msg, err := s.createSingleContactInfoCreateCredentialMsg(provider, userFindCredentialPC, corrected, credentialType, referenceCredentialID, pin, ssIntervalPubKID, ssIntervalPubK)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, msg)
	}

	return msgs, nil
}

// decodeSubmittedKYCSession unwraps a session produced by the existing authenticate-kyc /
// authenticate-otp pair.  The correction flow reuses those endpoints unchanged -- authenticating a
// subject against the KYC on file is the same problem whether the outcome is a new credential or a
// corrected one.
func (s *EKycServer) decodeSubmittedKYCSession(encryptedSessionID string) (SubmittedKYCSessionID, *Provider, error) {
	var sessionID SubmittedKYCSessionID

	sessid := encryptedSessionID
	// only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)
		if err != nil {
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}

	if _, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID); err != nil {
		return sessionID, nil, err
	}

	provider := s.findProvider(sessionID.ProviderName)
	if provider == nil {
		return sessionID, nil, errors.New("invalid provider")
	}

	return sessionID, provider, nil
}
