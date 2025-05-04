package main

// EVERYTHING IN ONE FILE, NEED TO REFACTOR!!!

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"context"
	"flag"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"

	"github.com/amonsat/fullname_parser"

	//	"github.com/ignite/cli/ignite/pkg/protoc-gen-dart/data"
	twilio "github.com/twilio/twilio-go"
	verify "github.com/twilio/twilio-go/rest/verify/v2"

	// use gin for web server
	"github.com/gin-gonic/gin"

	"bytes"
	"os"
	"strings"

	//	"encoding/hex"

	"github.com/pariz/gountries"

	//	"crypto/sha256"

	"github.com/spf13/cobra"

	"github.com/cosmos/cosmos-sdk/client/flags"

	//	"github.com/cosmos/cosmos-sdk/client/rpc"
	sdk "github.com/cosmos/cosmos-sdk/types"
	//	authcmd "github.com/cosmos/cosmos-sdk/x/auth/client/cli"

	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/edgelesssys/ego/ecrypto"

	//	"github.com/edgelesssys/ego/enclave"

	//  "github.com/evmos/ethermint/encoding"
	//  "github.com/c3qtech/qadena/app"
	qadenaflags "github.com/cosmos/cosmos-sdk/client/flags"
	cmdcfg "qadena_v3/cmd/config"
	qadenakr "qadena_v3/crypto/keyring"
	nstypes "qadena_v3/x/nameservice/types"
	qadenatx "qadena_v3/x/qadena/client/tx"
	c "qadena_v3/x/qadena/common"
	"qadena_v3/x/qadena/types"

	//	"google.golang.org/grpc/codes"
	//	"google.golang.org/grpc/status"

	//	"github.com/cosmos/cosmos-sdk/client/config"

	"github.com/cosmos/cosmos-sdk/client"

	"github.com/cosmos/cosmos-sdk/crypto/keyring"
	//	"github.com/c3qtech/qadena/app"

	//	"sort"
	"time"

	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/cometbft/cometbft/crypto/tmhash"
	//"github.com/cometbft/cometbft/libs/log"
	"cosmossdk.io/log"

	"io/ioutil"
	"math/big"
	"math/rand"

	//	"github.com/hashicorp/vault/shamir"

	//"github.com/cosmos/cosmos-sdk/store"
	cosmossdkiolog "cosmossdk.io/log"
	"cosmossdk.io/store"

	//	storetypes "github.com/cosmos/cosmos-sdk/store/types"
	storemetrics "cosmossdk.io/store/metrics"
	storetypes "cosmossdk.io/store/types"
	tmdb "github.com/cosmos/cosmos-db"

	//	"github.com/cosmos/cosmos-sdk/store/prefix"

	tmproto "github.com/cometbft/cometbft/proto/tendermint/types"
	amino "github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"

	//	enccodec "github.com/evmos/evmos/v18/encoding/codec"

	proto "github.com/cosmos/gogoproto/proto"
)

// Providers are the ones that send KYC to tne enclave
type RegisterKYCProviderRequest struct {
	Name            string `json:"name"`
	ArmorPrivKey    string `json:"armor-priv-key"`
	ArmorPassPhrase string `json:"armor-pass-phrase"`
	FriendlyName    string `json:"friendly-name"`
	Logo            string `json:"logo"`
}

type KYCRecord struct {
	PhoneNumber         string                               `json:"phone-number"`
	Email               string                               `json:"email"`
	PIN                 string                               `json:"pin"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type BulkSubmitKYCRequest struct {
	ProviderName string `json:"provider-name"`
	// array of KYCRecord
	KYCRecords []KYCRecord `json:"kyc-records"`
}

type BulkSubmitKYCResponse struct {
	Status string `json:"status"`
}

type SubmitKYCRequest struct {
	ProviderName        string                               `json:"provider-name"`
	PhoneNumber         string                               `json:"phone-number"`
	Email               string                               `json:"email"`
	PIN                 string                               `json:"pin"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type SubmitKYCResponse struct {
	CredentialAddress   string                               `json:"credential-address"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
	Logo                string                               `json:"logo"`
	error               string                               `json:"error"`
}

// NewKYCRequest sends in 2 images

type NewKYCSessionID struct {
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type NewKYCResponse struct {
	SessionID string `json:"session-id"`
}

type NotifyUserNewKYCRequest struct {
	ProviderName string `json:"provider-name"`
	PhoneNumber  string `json:"phone-number"`
	PIN          string `json:"pin"`
	SessionID    string `json:"session-id"`
}

type NotifyUserNewKYCSessionID struct {
	ProviderName        string                               `json:"provider-name"`
	PhoneNumber         string                               `json:"phone-number"`
	PIN                 string                               `json:"pin"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type NotifyUserNewKYCResponse struct {
	SessionID string `json:"session-id"`
}

type LivenessURLNewKYCRequest struct {
	SessionID string `json:"session-id"`
}

type LivenessURLNewKYCResponse struct {
	LivenessURL string `json:"liveness-url"`
}

type ValidateLivenessNewKYCRequest struct {
	SessionID string `json:"session-id"`
}

type ValidateLivenessNewKYCResponse struct {
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
	SessionID           string                               `json:"session-id"`
	Logo                string                               `json:"logo"`
}

type SubmitNewKYCRequest struct {
	SessionID string `json:"session-id"`
}

type AuthenticateUserNewKYCRequest struct {
	SessionID string `json:"session-id"`
	OTP       string `json:"otp"`
	PIN       string `json:"pin"`
}

type AuthenticateUserNewKYCSessionID struct {
	ProviderName        string                               `json:"provider-name"`
	PhoneNumber         string                               `json:"phone-number"`
	PIN                 string                               `json:"pin"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type AuthenticateUserNewKYCResponse struct {
	SessionID string `json:"session-id"`
}

type ReuseKYCRequest struct {
	ProviderName     string `json:"provider-name"`
	PhoneNumber      string `json:"phone-number"`
	LastName         string `json:"last-name"`
	FromProviderName string `json:"from-provider-name"`
}

type ReuseKYCResponse struct {
	SessionID string `json:"session-id"`
}

type NotifyUserReuseKYCRequest struct {
	ProviderName string `json:"provider-name"`
	SessionID    string `json:"session-id"`
}

type NotifyUserReuseKYCResponse struct {
}

type AuthenticateUserReuseKYCRequest struct {
	ProviderName string `json:"provider-name"`
	SessionID    string `json:"session-id"`
	OTP          string `json:"otp"`
	PIN          string `json:"pin"`
}

type AuthenticateUserReuseKYCResponse struct {
}

// V2 structs

type BeginKYCRequest struct {
	ProviderName string `json:"provider-name"`
	PhoneNumber  string `json:"phone-number"`
}

type BeginKYCSessionID struct {
	ProviderName string `json:"provider-name"`
	PhoneNumber  string `json:"phone-number"`
}

type BeginKYCResponse struct {
	SessionID string `json:"session-id"`
	Error     string `json:"error"`
}

type AuthenticateKYCRequest struct {
	FromProviderName string `json:"from-provider-name"`
	SessionID        string `json:"session-id"`
	OTP              string `json:"otp"`
	PIN              string `json:"pin"`
	LastName         string `json:"last-name"`
}

type AuthenticateOTPRequest struct {
	SessionID string `json:"session-id"`
	OTP       string `json:"otp"`
}

type AuthenticateKYCSessionID struct {
	ProviderName          string `json:"provider-name"`
	FromProviderName      string `json:"from-provider-name"`
	PhoneNumber           string `json:"phone-number"`
	ReferenceCredentialID string `json:"from-provider-credential-pc"`
	Reusable              bool   `json:"reusable"`

	PersonalInfo types.EncryptablePersonalInfo `json:"personal-info"`
}

type AuthenticateKYCResponse struct {
	SessionID        string                        `json:"session-id"`
	Reusable         bool                          `json:"reusable"`
	FromProviderName string                        `json:"from-provider-name"`
	PersonalInfo     types.EncryptablePersonalInfo `json:"personal-info"`
	Error            string                        `json:"error"`
}

type ConfirmReuseKYCRequest struct {
	SessionID                         string `json:"session-id"`
	UserFindCredentialPedersenCommmit string `json:"user-claim-pc"` // hex-encoded compressed pedersen commit
}

type ConfirmNewKYCRequest struct {
	SessionID string `json:"session-id"`
}

type ConfirmNewKYCSessionID struct {
	AuthenticateKYCSessionID string `json:"authenticate-kyc-session-id"`
	AdvaiH5URL               string `json:"advai-h5-url"`
}

type ConfirmNewKYCResponse struct {
	URL         string `json:"url"`
	ReferenceID string `json:"reference-id"`
	Error       string `json:"error"`
}

type SubmittedKYCSessionID struct {
	ProviderName        string                               `json:"provider-name"`
	PhoneNumber         string                               `json:"phone-number"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
}

type StatusKYCResponse struct {
	SessionID           string                               `json:"session-id"`
	PhoneNumber         string                               `json:"phone-number"`
	PersonalInfoDetails types.EncryptablePersonalInfoDetails `json:"personal-info-details"`
	Error               string                               `json:"error"`
}

type SubmitNewKYCv2Request struct {
	SessionID  string `json:"session-id"`
	PIN        string `json:"pin"`
	FirstName  string `json:"first-name"`
	MiddleName string `json:"middle-name"`
}

// EKycServer is used to implement the enclave grpc server
type EKycServer struct {
	types.UnimplementedQadenaEnclaveServer

	ServerCtx     sdk.Context
	CacheCtx      sdk.Context
	CacheCtxWrite func()
	Cdc           *amino.ProtoCodec
	StoreKey      storetypes.StoreKey

	privateEnclaveParams PrivateEnclaveParams

	HomePath    string
	RealEnclave bool
}

type storedEnclaveParams struct {
	PrivateEnclaveParams PrivateEnclaveParams
}

type ReuseKYCSessionID struct {
	// same as ReuseKYCRequest
	ReuseKYCRequest
}

// CONSTANTS

var CollectNewKYCURL = "http://ekyc.ngrok.app/ekyc/2.0.0/collect-new-kyc/"

var TwilioAccountSid = "ACxxxx"
var TwilioAuthToken = "xxxx"
var TwilioVerificationService = "VAxxxx"

var AdvanceAIAccessKey = "xxxx"
var AdvanceAISecretKey = "xxxx"
var AdvanceAIJourneyID = "xxxx" // from eKYCPH flow, ravillarica@traxiontech.net account

var AdvaiStartTransactionURL = "https://sandbox-oop-api.advai.net/intl/openapi/sdk/v2/trans/start"
var AdvaiRetrieveAnInquiryURL = "https://sandbox-oop-api.advai.net/openapi/onestop/inquiry/info"

type AdvanceAIGenerateTokenResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Token       string `json:"token"`
		ExpiredTime int64  `json:"expiredTime"`
	} `json:"data"`
	Extra           string `json:"extra"`
	TransactionId   string `json:"transactionId"`
	PricingStrategy string `json:"pricingStrategy"`
}

type AdvanceAIGetTokenResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Url         string `json:"url"`
		SignatureID string `json:"signatureId"`
	} `json:"data"`
	Extra           string `json:"extra"`
	TransactionId   string `json:"transactionId"`
	PricingStrategy string `json:"pricingStrategy"`
}

type Front struct {
	IDNumber        *string   `json:"idNumber"`
	DocumentNumber  *string   `json:"documentNumber"`
	FullName        *string   `json:"fullName"`
	FullNameLocal   *string   `json:"fullNameLocal"`
	LastName        *string   `json:"lastName"`
	LastNameLocal   *string   `json:"lastNameLocal"`
	FirstName       *string   `json:"firstName"`
	FirstNameLocal  *string   `json:"firstNameLocal"`
	MiddleName      *string   `json:"middleName"`
	MiddleNameLocal *string   `json:"middleNameLocal"`
	Birthday        *string   `json:"birthday"`
	DobDay          *string   `json:"dobDay"`
	DobMonth        *string   `json:"dobMonth"`
	DobYear         *string   `json:"dobYear"`
	ExpiryDate      *string   `json:"expiryDate"`
	ExpiryDay       *string   `json:"expiryDay"`
	ExpiryMonth     *string   `json:"expiryMonth"`
	ExpiryYear      *string   `json:"expiryYear"`
	DaysToExpiry    *string   `json:"daysToExpiry"`
	IssueDate       *string   `json:"issueDate"`
	IssueDay        *string   `json:"issueDay"`
	IssueMonth      *string   `json:"issueMonth"`
	IssueYear       *string   `json:"issueYear"`
	DaysFromIssue   *string   `json:"daysFromIssue"`
	State           *string   `json:"state"`
	City            *string   `json:"city"`
	District        *string   `json:"district"`
	Subdistrict     *string   `json:"subdistrict"`
	FullAddress     *string   `json:"fullAddress"`
	Postcode        *string   `json:"postcode"`
	PlaceOfBirth    *string   `json:"placeOfBirth"`
	IssuerAuthority *string   `json:"issuerAuthority"`
	IssuerPlace     *string   `json:"issuerPlace"`
	Gender          *string   `json:"gender"`
	Height          *string   `json:"height"`
	Weight          *string   `json:"weight"`
	EyeColor        *string   `json:"eyeColor"`
	BloodType       *string   `json:"bloodType"`
	Religion        *string   `json:"religion"`
	Nationality     *string   `json:"nationality"`
	IssuerCountry   *string   `json:"issuerCountry"`
	CountryCode     *string   `json:"countryCode"`
	PassportType    *string   `json:"passportType"`
	VehicleClass    *string   `json:"vehicleClass"`
	Restrictions    *string   `json:"restrictions"`
	Endorsement     *string   `json:"endorsement"`
	Side            *string   `json:"side"`
	Others          *struct{} `json:"others"`
}

type Back struct {
	IDNumber        *string   `json:"idNumber"`
	DocumentNumber  *string   `json:"documentNumber"`
	FullName        *string   `json:"fullName"`
	FullNameLocal   *string   `json:"fullNameLocal"`
	LastName        *string   `json:"lastName"`
	LastNameLocal   *string   `json:"lastNameLocal"`
	FirstName       *string   `json:"firstName"`
	FirstNameLocal  *string   `json:"firstNameLocal"`
	MiddleName      *string   `json:"middleName"`
	MiddleNameLocal *string   `json:"middleNameLocal"`
	Birthday        *string   `json:"birthday"`
	DobDay          *string   `json:"dobDay"`
	DobMonth        *string   `json:"dobMonth"`
	DobYear         *string   `json:"dobYear"`
	ExpiryDate      *string   `json:"expiryDate"`
	ExpiryDay       *string   `json:"expiryDay"`
	ExpiryMonth     *string   `json:"expiryMonth"`
	ExpiryYear      *string   `json:"expiryYear"`
	DaysToExpiry    *string   `json:"daysToExpiry"`
	IssueDate       *string   `json:"issueDate"`
	IssueDay        *string   `json:"issueDay"`
	IssueMonth      *string   `json:"issueMonth"`
	IssueYear       *string   `json:"issueYear"`
	DaysFromIssue   *string   `json:"daysFromIssue"`
	State           *string   `json:"state"`
	City            *string   `json:"city"`
	District        *string   `json:"district"`
	Subdistrict     *string   `json:"subdistrict"`
	FullAddress     *string   `json:"fullAddress"`
	Postcode        *string   `json:"postcode"`
	PlaceOfBirth    *string   `json:"placeOfBirth"`
	IssuerAuthority *string   `json:"issuerAuthority"`
	IssuerPlace     *string   `json:"issuerPlace"`
	Gender          *string   `json:"gender"`
	Height          *string   `json:"height"`
	Weight          *string   `json:"weight"`
	EyeColor        *string   `json:"eyeColor"`
	BloodType       *string   `json:"bloodType"`
	Religion        *string   `json:"religion"`
	Nationality     *string   `json:"nationality"`
	IssuerCountry   *string   `json:"issuerCountry"`
	CountryCode     *string   `json:"countryCode"`
	PassportType    *string   `json:"passportType"`
	VehicleClass    *string   `json:"vehicleClass"`
	Restrictions    *string   `json:"restrictions"`
	Endorsement     *string   `json:"endorsement"`
	Side            *string   `json:"side"`
	Others          *struct{} `json:"others"`
}

type CrossCheck struct {
	IDNumber *string `json:"idNumber"`
}

type AgeVerification struct {
	Age    *int    `json:"age"`
	Result *string `json:"result"`
}

type ExpiryDateVerification struct {
	DaysToExpiry *int    `json:"daysToExpiry"`
	Result       *string `json:"result"`
}

type Mrz struct {
	IssuerCountry  *string `json:"issuerCountry"`
	PassportType   *string `json:"passportType"`
	FirstName      *string `json:"firstName"`
	LastName       *string `json:"lastName"`
	IDNumber       *string `json:"idNumber"`
	Birthday       *string `json:"birthday"`
	Nationality    *string `json:"nationality"`
	Gender         *string `json:"gender"`
	ExpiryDate     *string `json:"expiryDate"`
	DocumentNumber *string `json:"documentNumber"`
}

type MrzCheck struct {
	IDNumber     *string `json:"idNumber"`
	PassportType *string `json:"passportType"`
	FirstName    *string `json:"firstName"`
	LastName     *string `json:"lastName"`
	Birthday     *string `json:"birthday"`
	Nationality  *string `json:"nationality"`
	Gender       *string `json:"gender"`
	ExpiryDate   *string `json:"expiryDate"`
}

type AdvanceAIUnifiedIDCardOCRResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Front                  Front                  `json:"front"`
		Back                   Front                  `json:"back"`
		CrossCheck             CrossCheck             `json:"crossCheck"`
		AgeVerification        AgeVerification        `json:"ageVerification"`
		ExpiryDateVerification ExpiryDateVerification `json:"expiryDateVerification"`
		Mrz                    Mrz                    `json:"mrz"`
		MrzCheck               MrzCheck               `json:"mrzCheck"`
	} `json:"data"`
	Extra           string `json:"extra"`
	TransactionId   string `json:"transactionId"`
	PricingStrategy string `json:"pricingStrategy"`
}

var ClientCtx client.Context
var RootCmd *cobra.Command

var testSignerID = "test-signer-id"
var testUniqueID = "test-unique-id"

var testSeal bool = true

var printTxSize bool = true

var sendTwilio bool = false

var BubbleProduction bool = true

func (s *EKycServer) SealWithProductKey(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.SealWithProductKey(b, nil)

		if err != nil {
			c.LoggerError(logger, "sealing error "+err.Error())
			return
		}
	} else {
		ret = append([]byte(testSignerID), b...)
		err = nil
	}
	return
}

func (s *EKycServer) SealWithUniqueKey(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.SealWithUniqueKey(b, nil)

		if err != nil {
			c.LoggerError(logger, "sealing error "+err.Error())
			return
		}
	} else {
		ret = append([]byte(testUniqueID), b...)
		err = nil
	}
	return
}

func (s *EKycServer) MustSeal(b []byte) (ret []byte) {
	var err error
	ret, err = s.SealWithProductKey(b)
	if err != nil {
		panic("Could not seal " + err.Error())
	}
	return
}

func (s *EKycServer) MustUnseal(b []byte) (ret []byte) {
	var err error
	ret, err = s.Unseal(b)
	if err != nil {
		panic("Could not seal " + err.Error())
	}
	return
}

func (s *EKycServer) Unseal(b []byte) (ret []byte, err error) {
	if s.RealEnclave {
		ret, err = ecrypto.Unseal(b, nil)

		if err != nil {
			c.LoggerError(logger, "unsealing error "+err.Error())
			return
		}
	} else {
		if bytes.HasPrefix(b, []byte(testUniqueID)) {
			c.LoggerDebug(logger, "unsealing with unique id")
			err = nil
			l := len(testUniqueID)

			x := b[l:]
			c.LoggerDebug(logger, "x "+string(x))
			ret = x
		} else if bytes.HasPrefix(b, []byte(testSignerID)) {
			c.LoggerDebug(logger, "unsealing with product id")
			err = nil
			ret = b[len(testSignerID):]
			c.LoggerDebug(logger, "ret "+string(ret))
		} else {
			err = errors.New("Couldn't unseal, unrecognized prefix")
		}
	}
	return
}

var logger log.Logger

type Provider struct {
	FriendlyName string
	Name         string
	WalletID     string
	WalletAddr   string
	ArmorPrivK   string
	PrivK        string
	PubK         string
	Logo         string
}

// these are never shared with other enclaves
type PrivateEnclaveParams struct {
	Providers []Provider

	EKYCName       string
	EKYCWalletID   string
	EKYCArmorPrivK string
	EKYCPrivK      string
	EKYCPubK       string
}

// end of never shared

const (
	EnvPrefix       = "QADENA"
	ArmorPassPhrase = "8675309" // this is only used in-process, in the enclave, does not affect security
)

func (s *EKycServer) initServer(ekycName string, ekycArmorPrivK string, ekycArmorPassPhrase string) {
	kb := ClientCtx.Keyring

	if s.privateEnclaveParams.EKYCPubK != "" {
		c.LoggerInfo(logger, "ekyc already initialized")
		return
	}

	c.LoggerDebug(logger, "Importing ekyc privk")

	err := kb.ImportPrivKey(ekycName, ekycArmorPrivK, ekycArmorPassPhrase)

	if err != nil {
		c.LoggerError(logger, "couldn't import privk "+err.Error())
		return
	}

	walletID, _, pubK, privK, armorPrivK, err := c.GetAddressByName(ClientCtx, ekycName, ArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't get address for "+ekycName+" "+err.Error())
		return
	}

	s.privateEnclaveParams.EKYCName = ekycName
	s.privateEnclaveParams.EKYCWalletID = walletID
	s.privateEnclaveParams.EKYCArmorPrivK = armorPrivK
	s.privateEnclaveParams.EKYCPrivK = privK
	s.privateEnclaveParams.EKYCPubK = pubK
}

func (s *EKycServer) saveEnclaveParams() bool {
	ep := storedEnclaveParams{
		PrivateEnclaveParams: s.privateEnclaveParams,
	}

	c.LoggerDebug(logger, "saveEnclaveParams "+c.PrettyPrint(ep))

	b, err := json.Marshal(ep)

	var b2 []byte

	if testSeal {
		b2, err = json.Marshal(ep)
	}

	if err != nil {
		c.LoggerError(logger, "saveEnclaveParams marshal error "+err.Error())
		return false
	}

	c.LoggerDebug(logger, "sealing with product key (encrypting)")
	b, err = s.SealWithProductKey(b)

	if testSeal {
		b2, err = s.SealWithProductKey(b2)
	}

	if err != nil {
		c.LoggerError(logger, "sealing error "+err.Error())
		return false
	}

	err = os.WriteFile(s.HomePath+"/enclave_config/ekyc_enclave_params.json", b, 0644)
	if testSeal {
		err = os.WriteFile(s.HomePath+"/enclave_config/ekyc_enclave_params_backup.json", b2, 0644)
	}

	if err != nil {
		c.LoggerError(logger, "err writing file "+err.Error())
		return false
	}

	c.LoggerDebug(logger, "saved")

	return true
}

func (s *EKycServer) loadEnclaveParams() bool {
	filename := s.HomePath + "/enclave_config/ekyc_enclave_params.json"
	fileBytes, err := ioutil.ReadFile(filename)

	if err != nil {
		c.LoggerInfo(logger, "Couldn't read file "+filename+" but this is ok if the ekyc_enclave has not yet been initialized.")
		return false
	} else {
		c.LoggerInfo(logger, "Read file "+filename)
	}

	c.LoggerDebug(logger, "unsealing with product key (decrypting)")
	fileBytes, err = s.Unseal(fileBytes)

	if err != nil {
		c.LoggerError(logger, "unsealing error "+err.Error())
		return false
	}

	var ep storedEnclaveParams

	err = json.Unmarshal([]byte(fileBytes), &ep)

	if err != nil {
		c.LoggerError(logger, "Couldn't unmarshal fileBytes")
		return false
	}

	c.LoggerDebug(logger, "storedenclaveParams "+c.PrettyPrint(ep))

	s.privateEnclaveParams = ep.PrivateEnclaveParams

	// populate our keyring

	kb := ClientCtx.Keyring

	// populate keyring with providers
	for _, provider := range s.privateEnclaveParams.Providers {
		err = kb.ImportPrivKey(provider.Name, provider.ArmorPrivK, ArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import privk "+err.Error())
			return false
		}
	}

	if s.privateEnclaveParams.EKYCName != "" && s.privateEnclaveParams.EKYCArmorPrivK != "" {
		// populate keyring with ekyc
		err = kb.ImportPrivKey(s.privateEnclaveParams.EKYCName, s.privateEnclaveParams.EKYCArmorPrivK, ArmorPassPhrase)

		if err != nil {
			c.LoggerError(logger, "couldn't import privk "+err.Error())
			return false
		}
	}

	return true
}

func (s *EKycServer) queryFindCredential(provider *Provider, findCredentialPC c.PedersenCommit, p proto.Message, credentialID *string) (exists bool, err error) {
	queryClientCtx, err := client.ReadPersistentCommandFlags(ClientCtx, RootCmd.Flags())

	if err != nil {
		return
	}

	queryClient := types.NewQueryClient(queryClientCtx)

	credPubKey := provider.PubK
	credPrivateKey := provider.PrivK

	fmt.Println("credPubKey", credPubKey, "credPrivateKey", credPrivateKey)

	fmt.Println("findCredentialPC", c.PrettyPrint(findCredentialPC))

	proofPC := c.NewPedersenCommit(findCredentialPC.A, nil)

	checkPC := c.SubPedersenCommitNoMinCheck(&findCredentialPC, proofPC)

	fmt.Println("proofPC", c.PrettyPrint(proofPC))

	fmt.Println("checkPC", c.PrettyPrint(checkPC))

	if c.DebugAmounts {
	} else {
		proofPC.A = c.BigIntZero
		proofPC.X = c.BigIntZero
	}

	if !c.ValidateSubPedersenCommit(&findCredentialPC, proofPC, checkPC) {
		fmt.Println("failed to validate checkPC - credentialPC - proofPC = 0")
	}

	ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ClientCtx, types.SSNodeID, types.SSNodeType)
	if err != nil {
		return
	}

	fmt.Println("ssIntervalPubKID", ssIntervalPubKID)
	fmt.Println("ssIntervalPubK", ssIntervalPubK)

	encUserCredentialPubKIntervalSSPubK := c.MarshalAndBEncrypt(ssIntervalPubK, credPubKey)
	encProofPCIntervalSSPubK := c.ProtoMarshalAndBEncrypt(ssIntervalPubK, c.ProtoizeBPedersenCommit(proofPC))
	encCheckPCIntervalSSPubK := c.ProtoMarshalAndBEncrypt(ssIntervalPubK, c.ProtoizeEncryptablePedersenCommit(checkPC))
	credentialPC := findCredentialPC.C.Bytes()

	params := &types.QueryFindCredentialRequest{
		CredentialPC:                        credentialPC,
		CredentialType:                      types.PersonalInfoCredentialType,
		SSIntervalPubKID:                    ssIntervalPubKID,
		EncUserCredentialPubKSSIntervalPubK: encUserCredentialPubKIntervalSSPubK,
		EncProofPCSSIntervalPubK:            encProofPCIntervalSSPubK,
		EncCheckPCSSIntervalPubK:            encCheckPCIntervalSSPubK,
	}

	res, err := queryClient.FindCredential(context.Background(), params)

	if err != nil && strings.Contains(err.Error(), "Credential does not exist") {
		exists = false
		err = nil
		return
	}

	if err != nil {
		return
	}

	ClientCtx.PrintProto(res)

	if p != nil {
		_, err = c.BDecryptAndProtoUnmarshal(credPrivateKey, res.EncPersonalInfoUserCredentialPubK, p)
		if err != nil {
			fmt.Println("couldn't decrypt personal info")
			return
		}

		fmt.Println("info", c.PrettyPrint(p))
	}

	if credentialID != nil {
		//	var credID string
		_, err = c.BDecryptAndUnmarshal(credPrivateKey, res.EncCredentialIDUserCredentialPubK, credentialID)
		if err != nil {
			fmt.Println("couldn't get decrypt credentialID")
			return
		}
		//	*credentialID = credID

		fmt.Println("credentialID", *credentialID)
	}

	exists = true

	return
}

// authenticateUserReuseKYCRequest
func (s *EKycServer) authenticateUserReuseKYC(context *gin.Context) {
	// print the request body

	/*
		body, _ := ioutil.ReadAll(context.Request.Body)
		c.LoggerDebug(logger, "authenticateUserReuseKYCRequest body", string(body))
	*/

	var authenticateUserReuseKYCRequest AuthenticateUserReuseKYCRequest

	if err := context.ShouldBindJSON(&authenticateUserReuseKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "authenticateUserReuseKYCRequest "+c.PrettyPrint(authenticateUserReuseKYCRequest))

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID ReuseKYCSessionID

	sessid := authenticateUserReuseKYCRequest.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(sessionID.LastName))
	phoneNumber := strings.TrimSpace(strings.ToLower(sessionID.PhoneNumber))

	// find the provider
	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	// find the fromProvider
	var fromProvider *Provider = s.findProvider(sessionID.FromProviderName)
	if fromProvider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid fromProvider"})
		return
	}

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationCheckParams{}
		params.SetTo(sessionID.PhoneNumber)
		params.SetCode(authenticateUserReuseKYCRequest.OTP)

		resp, err := client.VerifyV2.CreateVerificationCheck(TwilioVerificationService, params)
		if err != nil {
			fmt.Println(err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
				if *resp.Status == "pending" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
					return
				} else if *resp.Status != "approved" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "bad status"})
					return
				}
			} else {
				fmt.Println(resp.Status)
				context.JSON(http.StatusBadRequest, gin.H{"error": "nil status"})
				return
			}
		}

	} else {
		if authenticateUserReuseKYCRequest.OTP == "111111" {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
			return
		}
	}

	// good path

	var p types.EncryptablePersonalInfo
	var referenceCredentialID string //	var credentialID string

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(fromProvider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))
	fromProviderFindCredentialPC := c.NewPedersenCommit(all, pin)

	exists, err := s.queryFindCredential(fromProvider, *fromProviderFindCredentialPC, &p, &referenceCredentialID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !exists {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential does not exist for the fromProvider"})
		return
	}

	// print the fromProviderFindCredentialPC
	fmt.Println("fromProviderFindCredentialPC", c.PrettyPrint(fromProviderFindCredentialPC))

	/*
		// check if the PIN matches
		if p.PIN != authenticateUserReuseKYCRequest.PIN {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid PIN"})
			return
		}
	*/

	// send
	pin = big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all = big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))
	findCredentialPC := c.NewPedersenCommit(all, pin)
	s.createAndBroadcastPersonalInfoCreateCredentialMsg(context, provider, findCredentialPC, &p, referenceCredentialID)
}

// implement gin post method for reuseKYC
func (s *EKycServer) reuseKYC(context *gin.Context) {
	var reuseKYCRequest ReuseKYCRequest
	if err := context.ShouldBindJSON(&reuseKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "reuseKYCRequest "+c.PrettyPrint(reuseKYCRequest))

	// find the provider
	var provider *Provider = s.findProvider(reuseKYCRequest.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	// find the fromProvider
	var fromProvider *Provider = s.findProvider(reuseKYCRequest.FromProviderName)
	if fromProvider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid fromProvider"})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(reuseKYCRequest.LastName))
	phoneNumber := strings.TrimSpace(strings.ToLower(reuseKYCRequest.PhoneNumber))

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))
	findCredentialPC := c.NewPedersenCommit(all, pin)

	// check if the provider who's asking already has it

	// find the credential by XY
	exists, err := s.queryFindCredential(provider, *findCredentialPC, nil, nil)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential already exists for the requesting provider"})
		return
	}

	pin = big.NewInt(0).SetBytes(tmhash.Sum([]byte(fromProvider.PrivK)))
	all = big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))
	findCredentialPC = c.NewPedersenCommit(all, pin)

	exists, err = s.queryFindCredential(fromProvider, *findCredentialPC, nil, nil)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !exists {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential does not exist for the fromProvider"})
		return
	}

	// print the fromProviderFindCredentialPC
	fmt.Println("fromProviderFindCredentialPC", c.PrettyPrint(findCredentialPC))

	// create ReuseKYCSessionID

	reuseKYCSessionID := ReuseKYCSessionID{
		reuseKYCRequest,
	}

	// encrypt reuseKYCSessionID with provider pubk

	encReuseKYCSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, reuseKYCSessionID)
	if c.TextBasedEncrypt {
		encReuseKYCSessionID = hex.EncodeToString([]byte(encReuseKYCSessionID))
	}

	context.JSON(http.StatusOK, ReuseKYCResponse{SessionID: encReuseKYCSessionID})
}

// authenticateUserNewKYCRequest
func (s *EKycServer) authenticateUserNewKYC(context *gin.Context) {
	var authenticateUserNewKYCRequest AuthenticateUserNewKYCRequest

	if err := context.ShouldBindJSON(&authenticateUserNewKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "authenticateUserNewKYC "+c.PrettyPrint(authenticateUserNewKYCRequest))

	// decrypt EncSessionID
	var sessionID NotifyUserNewKYCSessionID

	sessid := authenticateUserNewKYCRequest.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationCheckParams{}
		params.SetTo(sessionID.PhoneNumber)
		params.SetCode(authenticateUserNewKYCRequest.OTP)

		resp, err := client.VerifyV2.CreateVerificationCheck(TwilioVerificationService, params)
		if err != nil {
			fmt.Println(err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
				if *resp.Status == "pending" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
					return
				} else if *resp.Status != "approved" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "bad status"})
					return
				}
			} else {
				fmt.Println(resp.Status)
				context.JSON(http.StatusBadRequest, gin.H{"error": "nil status"})
				return
			}
		}
	} else {
		if authenticateUserNewKYCRequest.OTP == "111111" {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
			return
		}
	}

	// good path
	// return session id

	// create AuthenticateUserNewKYCSessionID

	authenticateUserNewKYCSessionID := AuthenticateUserNewKYCSessionID{
		ProviderName:        sessionID.ProviderName,
		PhoneNumber:         sessionID.PhoneNumber,
		PIN:                 sessionID.PIN,
		PersonalInfoDetails: sessionID.PersonalInfoDetails,
	}

	// encrypt authenticateUserNewKYCSessionID with provider pubk

	encAuthenticateUserNewKYCSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, authenticateUserNewKYCSessionID)
	if c.TextBasedEncrypt {
		encAuthenticateUserNewKYCSessionID = hex.EncodeToString([]byte(encAuthenticateUserNewKYCSessionID))
	}

	c.LoggerDebug(logger, "OK encAuthenticateUserNewKYCSessionID "+encAuthenticateUserNewKYCSessionID)

	context.JSON(http.StatusOK, AuthenticateUserNewKYCResponse{SessionID: encAuthenticateUserNewKYCSessionID})
}

// implement gin post method for newKYC

func (s *EKycServer) newKYC(context *gin.Context) {

	// accept images in post body

	form, err := context.MultipartForm()
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	filefront := form.File["front"]

	if len(filefront) != 1 {
		context.JSON(http.StatusBadRequest, gin.H{"error": "front image is required"})
		return
	}

	front := filefront[0]
	uploadFilePath := filepath.Join(s.HomePath, "uploads")

	ct, err := os.CreateTemp(uploadFilePath, "*"+front.Filename)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	frontFileName := ct.Name()
	ct.Close()

	defer os.Remove(frontFileName)

	if err := context.SaveUploadedFile(front, frontFileName); err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
		return
	}
	fileback := form.File["back"]

	var backFileName string

	if len(fileback) == 1 {
		back := fileback[0]
		ct, err := os.CreateTemp(uploadFilePath, "*"+back.Filename)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		backFileName = ct.Name()
		ct.Close()

		defer os.Remove(backFileName)

		if err := context.SaveUploadedFile(back, backFileName); err != nil {
			context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
			return
		}
	}

	idType := form.Value["id-type"][0]

	if idType == "Driver's License" {
		idType = "DRIVING_LICENSE"
	} else if idType == "Passport" {
		idType = "PASSPORT"
	} else {
		// unsupported
		context.JSON(http.StatusBadRequest, gin.H{"error": "Unsupported ID Type"})
		return
	}

	token, err := s.generateToken()

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the token
	fmt.Println(token)

	// POST to https://sg-api.advance.ai/intl/openapi/face-identity/v4/unified-id-card-ocr
	// with the token in the header

	httpposturl := "https://sg-api.advance.ai/intl/openapi/face-identity/v4/unified-id-card-ocr"

	// body is multipart/form-data
	// frontImage, backImage, region

	buf, err := os.Open(frontFileName)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	fw, err := writer.CreateFormFile("frontFile", "front.jpg")

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = io.Copy(fw, buf)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if backFileName != "" {
		buf, err = os.Open(backFileName)

		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fw, err = writer.CreateFormFile("backFile", "back.jpg")
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		_, err = io.Copy(fw, buf)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	err = writer.WriteField("region", "PHL")
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = writer.WriteField("cardType", idType)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = writer.WriteField("returnEmpty", "true")
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = writer.Close()
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// create the http request

	request, err := http.NewRequest("POST", httpposturl, body)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// set the request header
	request.Header.Set("Content-Type", writer.FormDataContentType())
	request.Header.Set("X-ACCESS-TOKEN", token)

	// create the http client
	client := &http.Client{}

	// send the request
	response, err := client.Do(request)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// close the response body
	defer response.Body.Close()

	// read the response body
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the response body
	fmt.Println(string(responseBody))

	var ocrResponse AdvanceAIUnifiedIDCardOCRResponse

	// unmarshal the response body to the result map
	err = json.Unmarshal(responseBody, &ocrResponse)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the result
	fmt.Println(c.PrettyPrint(ocrResponse))

	// check if have first name, last name, middle name
	firstName := ocrResponse.Data.Front.FirstName
	if firstName == nil {
		firstName = ocrResponse.Data.Back.FirstName
	}

	lastName := ocrResponse.Data.Front.LastName
	if lastName == nil {
		lastName = ocrResponse.Data.Back.LastName
	}

	middleName := ocrResponse.Data.Front.MiddleName
	if middleName == nil {
		middleName = ocrResponse.Data.Back.MiddleName
	}

	birthdate := ocrResponse.Data.Front.Birthday
	if birthdate == nil {
		birthdate = ocrResponse.Data.Back.Birthday
	}

	gender := ocrResponse.Data.Front.Gender
	if gender == nil {
		gender = ocrResponse.Data.Back.Gender
	}

	// residency
	nationality := ocrResponse.Data.Front.Nationality
	if nationality == nil {
		nationality = ocrResponse.Data.Back.Nationality
	}

	if firstName == nil || lastName == nil || middleName == nil {
		// parse full name using amonsat
		var parsedFullName fullname_parser.ParsedName
		if ocrResponse.Data.Front.FullName != nil {
			parsedFullName = fullname_parser.ParseFullname(*ocrResponse.Data.Front.FullName)
		}
		if ocrResponse.Data.Back.FullName != nil {
			parsedFullName = fullname_parser.ParseFullname(*ocrResponse.Data.Back.FullName)
		}

		// do we have more info from parsedFullname? Compare with firstName, lastName, middleName

		if parsedFullName.First != "" && (firstName == nil || lastName == nil || middleName == nil) {
			firstName = &parsedFullName.First
			lastName = &parsedFullName.Last
			middleName = &parsedFullName.Middle
		}

	}

	if lastName == nil {
		context.JSON(http.StatusOK, gin.H{"error": "Invalid ID"})
		return
	}

	// create personalinfoDetails
	var pd types.EncryptablePersonalInfoDetails

	pd.FirstName = strings.ToLower(*firstName)
	pd.LastName = strings.ToLower(*lastName)
	pd.MiddleName = strings.ToLower(*middleName)
	// normalize ocrResponse.Data.Front.BirthDate

	// parse birthdate format mm/dd/yyyy
	t, err := time.Parse("2006/01/02", *birthdate)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	const shortForm = "2006-Jan-02"
	pd.Birthdate = t.Format(shortForm)

	pd.Gender = types.NormalizeGender(*gender)

	// do the gountries
	// normalize nationality using gountries

	query := gountries.New()

	countries := strings.Split(*nationality, ",")

	normalizedCountries := make([]string, len(countries))
	for i := range countries {
		var country gountries.Country
		country, err = query.FindCountryByAlpha(countries[i])
		if err != nil {
			country, err = query.FindCountryByName(countries[i])
			if err != nil {
				country, err = query.FindCountryByNativeName(countries[i])
				if err != nil {
					return
				}
			}
		}

		normalizedCountries[i] = country.Alpha2
	}

	pd.Citizenship = strings.Join(normalizedCountries, ",")
	pd.Residency = pd.Citizenship

	newKYCSessionID := NewKYCSessionID{
		PersonalInfoDetails: pd,
	}

	// encrypt newKYCSessionID with provider pubk

	encNewKYCSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, newKYCSessionID)
	if c.TextBasedEncrypt {
		encNewKYCSessionID = hex.EncodeToString([]byte(encNewKYCSessionID))
	}

	// print encNewKYCSessionID
	fmt.Println("encNewKYCSessionID", encNewKYCSessionID)

	context.JSON(http.StatusOK, NewKYCResponse{SessionID: encNewKYCSessionID})
}

// implement gin post method for notifyUserNewKYC
func (s *EKycServer) notifyUserNewKYC(context *gin.Context) {
	var newKYCRequest NotifyUserNewKYCRequest
	if err := context.ShouldBindJSON(&newKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "notifyUserNewKYC "+c.PrettyPrint(newKYCRequest))

	// find the provider
	var provider *Provider = s.findProvider(newKYCRequest.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID NewKYCSessionID

	sessid := newKYCRequest.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(sessionID.PersonalInfoDetails.LastName))
	phoneNumber := strings.TrimSpace(strings.ToLower(newKYCRequest.PhoneNumber))

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))
	findCredentialPC := c.NewPedersenCommit(all, pin)

	// check if the provider who's asking already has it

	// find the credential by XY
	exists, err := s.queryFindCredential(provider, *findCredentialPC, nil, nil)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		context.JSON(http.StatusOK, gin.H{"error": "Credential already exists for the requesting provider",
			"last-name":    lastName,
			"phone-number": phoneNumber})
		return
	}

	// print the fromProviderFindCredentialPC
	fmt.Println("findCredentialPC", c.PrettyPrint(findCredentialPC))

	// create NotifyUserNewKYCSessionID

	notifyUserNewKYCSessionID := NotifyUserNewKYCSessionID{
		ProviderName:        newKYCRequest.ProviderName,
		PhoneNumber:         phoneNumber,
		PersonalInfoDetails: sessionID.PersonalInfoDetails,
	}

	// encrypt notifyUserNewKYCSessionID with provider pubk

	encNotifyUserNewKYCSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, notifyUserNewKYCSessionID)
	if c.TextBasedEncrypt {
		encNotifyUserNewKYCSessionID = hex.EncodeToString([]byte(encNotifyUserNewKYCSessionID))
	}

	context.JSON(http.StatusOK, NotifyUserNewKYCResponse{SessionID: encNotifyUserNewKYCSessionID})
}

// implement gin post method for reuseKYC
func (s *EKycServer) notifyUserReuseKYCRequest(context *gin.Context) {

	if !sendTwilio {
		// respond ok
		context.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	var notifyUserReuseKYCRequest NotifyUserReuseKYCRequest

	if err := context.ShouldBindJSON(&notifyUserReuseKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "notifyUserReuseKYCRequest "+c.PrettyPrint(notifyUserReuseKYCRequest))

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID ReuseKYCSessionID

	sessid := notifyUserReuseKYCRequest.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationParams{}
		params.SetTo(sessionID.PhoneNumber)
		params.SetChannel("sms")

		resp, err := client.VerifyV2.CreateVerification(TwilioVerificationService, params)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			fmt.Println(err.Error())
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
			} else {
				fmt.Println(resp.Status)
			}
		}
	}

	context.JSON(http.StatusOK, gin.H{"status": "ok"})
	// context.JSON(http.StatusOK, NotifyUserReuseKYCResponse{})
}

func (s *EKycServer) createSingleContactInfoCreateCredentialMsg(provider *Provider, findCredentialPC *c.PedersenCommit, p *types.EncryptablePersonalInfo, credentialType string, referenceCredentialID string, pin *big.Int, ssIntervalPubKID string, ssIntervalPubK string) (msg *types.MsgCreateCredential, err error) {
	var sci types.EncryptableSingleContactInfo
	sci.Details = new(types.EncryptableSingleContactInfoDetails)

	sci.Nonce = p.Nonce
	sci.PIN = p.PIN
	if credentialType == types.FirstNamePersonalInfoCredentialType {
		sci.Details.Contact = p.Details.FirstName
	} else if credentialType == types.LastNamePersonalInfoCredentialType {
		sci.Details.Contact = p.Details.LastName
	} else if credentialType == types.MiddleNamePersonalInfoCredentialType {
		sci.Details.Contact = p.Details.MiddleName
	} else {
		err = errors.New("invalid credential type")
		return
	}

	all, _ := proto.Marshal(sci.Details)

	ccPubK := []c.VSharePubKInfo{
		c.VSharePubKInfo{PubK: ssIntervalPubK, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
	}

	encCredentialInfoVShare, credentialInfoVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &sci)

	if credentialInfoVShareBind == nil {
		fmt.Println("ERROR! ProtoMarshalAndVShareBEncrypt() failed!")
		// return err
		return nil, errors.New("could not ProtoMarshalAndVShareBEncrypt()")
	}

	credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum([]byte(all))), pin)

	if c.DebugAmounts {
	} else {
		credentialPC.A = c.BigIntZero
		credentialPC.X = c.BigIntZero
	}

	findCredentialProtoPC := c.ProtoizeBPedersenCommit(findCredentialPC)
	credentialProtoPC := c.ProtoizeBPedersenCommit(credentialPC)

	// create the "protoized" bind data
	protoCredentialInfoVShareBind := c.ProtoizeVShareBindData(credentialInfoVShareBind)

	credWalletID := provider.WalletID + "-" + strconv.FormatInt(time.Now().UnixMilli(), 16)

	fmt.Println("credWalletID", credWalletID)

	msg = types.NewMsgCreateCredential(
		provider.WalletAddr,
		credWalletID,
		credentialType,
		credentialProtoPC,
		protoCredentialInfoVShareBind,
		encCredentialInfoVShare,
		nil,
		nil,
		findCredentialProtoPC,
		s.privateEnclaveParams.EKYCWalletID,
		referenceCredentialID,
	)

	return msg, msg.ValidateBasic()
}

func (s *EKycServer) newPersonalInfo(pin, firstName, middleName, lastName, birthDate, citizenship, residency, gender string) (personalInfo *types.EncryptablePersonalInfo, err error) {
	// validate/normalize the data

	nonce := "nonce-" + strconv.Itoa(rand.Intn(1000))

	var p types.EncryptablePersonalInfo
	p.Details = new(types.EncryptablePersonalInfoDetails)
	p.PIN = pin
	p.Nonce = nonce
	p.Details.FirstName = strings.TrimSpace(strings.ToLower(firstName))
	p.Details.MiddleName = strings.TrimSpace(strings.ToLower(middleName))
	p.Details.LastName = lastName
	p.Details.Birthdate = birthDate
	p.Details.Citizenship = citizenship
	p.Details.Residency = residency
	p.Details.Gender = strings.ToLower(strings.TrimSpace(gender))

	const shortForm = "2006-Jan-02"
	t, err := time.Parse(shortForm, p.Details.Birthdate)
	if err != nil {
		return
	}
	p.Details.Birthdate = t.Format(shortForm)

	p.Details.Gender = types.NormalizeGender(p.Details.Gender)

	query := gountries.New()

	countries := strings.Split(p.Details.Citizenship, ",")
	normalizedCountries := make([]string, len(countries))
	for i := range countries {
		var country gountries.Country
		country, err = query.FindCountryByAlpha(countries[i])
		if err != nil {
			country, err = query.FindCountryByName(countries[i])
			if err != nil {
				country, err = query.FindCountryByNativeName(countries[i])
				if err != nil {
					return
				}
			}
		}

		//          fmt.Println("Country", c.PrettyPrint(country))
		normalizedCountries[i] = country.Alpha2
	}

	p.Details.Citizenship = strings.Join(normalizedCountries, ",")

	countries = strings.Split(p.Details.Residency, ",")
	normalizedCountries = make([]string, len(countries))
	for i := range countries {
		var country gountries.Country
		country, err = query.FindCountryByAlpha(countries[i])
		if err != nil {
			country, err = query.FindCountryByName(countries[i])
			if err != nil {
				country, err = query.FindCountryByNativeName(countries[i])
				if err != nil {
					return
				}
			}
		}
		//          fmt.Println("Country", c.PrettyPrint(country))
		normalizedCountries[i] = country.Alpha2
	}
	p.Details.Residency = strings.Join(normalizedCountries, ",")

	personalInfo = &p

	return
}

func (s *EKycServer) generateToken() (token string, err error) {
	httpposturl := "https://sg-api.advance.ai/openapi/auth/ticket/v1/generate-token"

	// create the request body

	timestamp := time.Now().UnixMilli() + 300000
	timeStampString := strconv.FormatInt(timestamp, 10)

	signature := AdvanceAIAccessKey + AdvanceAISecretKey + timeStampString

	signatureSHA256 := sha256.Sum256([]byte(signature))

	signature = hex.EncodeToString(signatureSHA256[:])

	// create the request body
	requestBody := gin.H{
		"accessKey": AdvanceAIAccessKey,
		"signature": signature,
		"timestamp": timeStampString,
	}

	// convert the request body to json
	jsonValue, _ := json.Marshal(requestBody)

	// create the http request
	request, err := http.NewRequest("POST", httpposturl, bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}

	// set the request header
	request.Header.Set("Content-Type", "application/json")

	// create the http client
	client := &http.Client{}

	// send the request
	response, err := client.Do(request)
	if err != nil {
		return
	}

	// close the response body
	defer response.Body.Close()

	// read the response body
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}

	// print the response body
	fmt.Println(string(responseBody))

	var generateTokenResponse AdvanceAIGenerateTokenResponse

	// unmarshal the response body to the result map
	err = json.Unmarshal(responseBody, &generateTokenResponse)
	if err != nil {
		return
	}

	// print the result
	fmt.Println(c.PrettyPrint(generateTokenResponse))

	// get the token from the result map
	token = generateTokenResponse.Data.Token

	return
}

func (s *EKycServer) validateLivenessNewKYC(context *gin.Context) {
	var validateLivenessNewKYCRequest ValidateLivenessNewKYCRequest
	if err := context.ShouldBindJSON(&validateLivenessNewKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "validateLivenessNewKYCRequest "+c.PrettyPrint(validateLivenessNewKYCRequest))

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID AuthenticateUserNewKYCSessionID

	sessid := validateLivenessNewKYCRequest.SessionID

	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// find provider
	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	// print the sessionID
	fmt.Println("sessionID", c.PrettyPrint(sessionID))

	// return the personalinfodetails
	context.JSON(http.StatusOK, ValidateLivenessNewKYCResponse{PersonalInfoDetails: sessionID.PersonalInfoDetails, SessionID: validateLivenessNewKYCRequest.SessionID, Logo: provider.Logo})
}

func (s *EKycServer) livenessURLNewKYC(context *gin.Context) {
	var livenessURLNewKYCRequest LivenessURLNewKYCRequest
	if err := context.ShouldBindJSON(&livenessURLNewKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "livenessURLNewKYCRequest "+c.PrettyPrint(livenessURLNewKYCRequest))

	token, err := s.generateToken()

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the token
	fmt.Println(token)

	// POST to https://sg-api.advance.ai/intl/openapi/face-identity/v2/h5/token
	// with the token in the header

	httpposturl := "https://sg-api.advance.ai/intl/openapi/face-identity/v2/h5/token"

	// body is returnUrl, failedReturnUrl, region

	// create the request body
	var requestBody gin.H

	if BubbleProduction {
		requestBody = gin.H{
			"tryCount":        "2",
			"returnUrl":       "https://ekycph.bubbleapps.io/new_ekyc_step_3?session_id=" + livenessURLNewKYCRequest.SessionID,
			"failedReturnUrl": "https://ekycph.bubbleapps.io/failed_liveness",
			"region":          "PHL",
		}
	} else {
		requestBody = gin.H{
			"returnUrl":       "https://ekycph.bubbleapps.io/version-test/new_ekyc_step_3?debug_mode=true&session_id=" + livenessURLNewKYCRequest.SessionID,
			"tryCount":        "1",
			"failedReturnUrl": "https://ekycph.bubbleapps.io/version-test/failed_liveness?debug_mode=true",
			//		"returnUrl":        "https://ekycph.bubbleapps.io/new_ekyc_step_3?session_id=" + livenessURLNewKYCRequest.SessionID,
			//		"failedReturnUrl":  "https://ekycph.bubbleapps.io/failed_liveness",
			"region": "PHL",
		}
	}

	// convert the request body to json
	jsonValue, _ := json.Marshal(requestBody)

	// print jsonValue
	fmt.Println("jsonValue", string(jsonValue))

	// create the http request

	request, err := http.NewRequest("POST", httpposturl, bytes.NewBuffer(jsonValue))

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// set the request header
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-ACCESS-TOKEN", token)

	// create the http client
	client := &http.Client{}

	// send the request
	response, err := client.Do(request)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// close the response body
	defer response.Body.Close()

	// read the response body
	responseBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the response body
	fmt.Println(string(responseBody))

	var getTokenResponse AdvanceAIGetTokenResponse

	// unmarshal the response body to the result map
	err = json.Unmarshal(responseBody, &getTokenResponse)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the result
	fmt.Println(c.PrettyPrint(getTokenResponse))

	// return the url
	context.JSON(http.StatusOK, LivenessURLNewKYCResponse{LivenessURL: getTokenResponse.Data.Url})
}

// implement gin post method for submitNewKYC
func (s *EKycServer) submitNewKYC(context *gin.Context) {
	var submitNewKYCRequest SubmitNewKYCRequest
	if err := context.ShouldBindJSON(&submitNewKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "submitNewKYCRequest "+c.PrettyPrint(submitNewKYCRequest))

	// decrypt sessionid
	var sessionID AuthenticateUserNewKYCSessionID

	sessid := submitNewKYCRequest.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the sessionID
	fmt.Println("sessionID", c.PrettyPrint(sessionID))

	// check if submitKYCRequest.ProviderID is a valid provider
	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(sessionID.PersonalInfoDetails.LastName))
	phoneNumber := strings.TrimSpace(strings.ToLower(sessionID.PhoneNumber))

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))

	findCredentialPC := c.NewPedersenCommit(all, pin)

	// find the credential by XY to see if it already exists on the chain for this provider
	var existingP types.EncryptablePersonalInfo
	var credentialID string

	exists, err := s.queryFindCredential(provider, *findCredentialPC, &existingP, &credentialID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		// credential already exists
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential already exists"})
		return
	}

	// we are here, so there was no previous credential, so we can create a new one

	p, err := s.newPersonalInfo(sessionID.PIN,
		sessionID.PersonalInfoDetails.FirstName,
		sessionID.PersonalInfoDetails.MiddleName,
		lastName,
		sessionID.PersonalInfoDetails.Birthdate,
		sessionID.PersonalInfoDetails.Citizenship,
		sessionID.PersonalInfoDetails.Residency,
		sessionID.PersonalInfoDetails.Gender)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.createAndBroadcastPersonalInfoCreateCredentialMsg(context, provider, findCredentialPC, p, "")
}

// implement gin post method for submitKYC
func (s *EKycServer) submitKYC(context *gin.Context) {
	var submitKYCRequest SubmitKYCRequest
	if err := context.ShouldBindJSON(&submitKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "submitKYCRequest "+c.PrettyPrint(submitKYCRequest))

	// check if submitKYCRequest.ProviderID is a valid provider
	var provider *Provider = s.findProvider(submitKYCRequest.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(submitKYCRequest.PersonalInfoDetails.LastName))
	phoneNumber := strings.TrimSpace(strings.ToLower(submitKYCRequest.PhoneNumber))

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))

	findCredentialPC := c.NewPedersenCommit(all, pin)

	// find the credential by XY to see if it already exists on the chain for this provider
	var existingP types.EncryptablePersonalInfo
	var credentialID string

	exists, err := s.queryFindCredential(provider, *findCredentialPC, &existingP, &credentialID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		// credential already exists
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential already exists"})
		return
	}

	// we are here, so there was no previous credential, so we can create a new one

	p, err := s.newPersonalInfo(submitKYCRequest.PIN,
		submitKYCRequest.PersonalInfoDetails.FirstName,
		submitKYCRequest.PersonalInfoDetails.MiddleName,
		lastName,
		submitKYCRequest.PersonalInfoDetails.Birthdate,
		submitKYCRequest.PersonalInfoDetails.Citizenship,
		submitKYCRequest.PersonalInfoDetails.Residency,
		submitKYCRequest.PersonalInfoDetails.Gender)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.createAndBroadcastPersonalInfoCreateCredentialMsg(context, provider, findCredentialPC, p, "")
}

// implement gin post method for bulkSubmitKYC
func (s *EKycServer) bulkSubmitKYC(context *gin.Context) {
	var bulkSubmitKYCRequest BulkSubmitKYCRequest
	if err := context.ShouldBindJSON(&bulkSubmitKYCRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the request
	c.LoggerDebug(logger, "bulkSubmitKYCRequest "+c.PrettyPrint(bulkSubmitKYCRequest))

	// check if bulkSubmitKYCRequest.ProviderID is a valid provider
	var provider *Provider = s.findProvider(bulkSubmitKYCRequest.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ClientCtx, types.SSNodeID, types.SSNodeType)
	if err != nil {
		return
	}
	fmt.Println("ssIntervalPubKID", ssIntervalPubKID, "ssIntervalPubK", ssIntervalPubK)

	// nodes who will be cc'd for the vshare
	ccPubK := []c.VSharePubKInfo{
		c.VSharePubKInfo{PubK: provider.PubK, NodeID: "", NodeType: ""},
		c.VSharePubKInfo{PubK: ssIntervalPubKID, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
	}

	bulkVShare := c.ProtoMarshalAndVShareBEncryptStep1(ccPubK)
	bulkHashVShare := c.ProtoMarshalAndVShareBEncryptStep1(ccPubK)

	bulkCredentials := make([]*types.BulkCredential, len(bulkSubmitKYCRequest.KYCRecords))

	for i, kycRecord := range bulkSubmitKYCRequest.KYCRecords {
		lastName := strings.TrimSpace(strings.ToLower(kycRecord.PersonalInfoDetails.LastName))
		phoneNumber := strings.TrimSpace(strings.ToLower(kycRecord.PhoneNumber))

		pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
		all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))

		findCredentialPC := c.NewPedersenCommit(all, pin)

		// find the credential by XY to see if it already exists on the chain for this provider
		var existingP types.EncryptablePersonalInfo
		var credentialID string

		exists, err := s.queryFindCredential(provider, *findCredentialPC, &existingP, &credentialID)

		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if exists {
			// credential already exists
			context.JSON(http.StatusBadRequest, gin.H{"error": "Credential already exists"})
			return
		}

		// we are here, so there was no previous credential, so we can create a new one

		p, err := s.newPersonalInfo(kycRecord.PIN,
			kycRecord.PersonalInfoDetails.FirstName,
			kycRecord.PersonalInfoDetails.MiddleName,
			lastName,
			kycRecord.PersonalInfoDetails.Birthdate,
			kycRecord.PersonalInfoDetails.Citizenship,
			kycRecord.PersonalInfoDetails.Residency,
			kycRecord.PersonalInfoDetails.Gender)

		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		allDetails, _ := proto.Marshal(p.Details)

		var credentialHash string
		firstMiddleLast := p.Details.LastName + "," + p.Details.MiddleName + "," + p.Details.FirstName

		credentialHash = c.Hash(firstMiddleLast)

		credWalletID := provider.WalletID + "-" + strconv.FormatInt(time.Now().UnixMilli(), 16)

		credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(allDetails)), pin)

		if c.DebugAmounts {
		} else {
			credentialPC.A = c.BigIntZero
			credentialPC.X = c.BigIntZero
		}

		credentialProtoPC := c.ProtoizeBPedersenCommit(credentialPC)
		encCredentialInfoVShare := c.ProtoMarshalAndVShareBEncryptStep2(bulkVShare, p)
		encCredentialHashVShare := c.ProtoMarshalAndVShareBEncryptStep2(bulkHashVShare, &types.EncryptableString{Value: credentialHash})
		findCredentialProtoPC := c.ProtoizeBPedersenCommit(findCredentialPC)

		bulkCredential := types.BulkCredential{
			CredentialID:                 credWalletID,
			CredentialPedersenCommit:     credentialProtoPC,
			EncCredentialInfoVShare:      encCredentialInfoVShare,
			EncCredentialHashVShare:      encCredentialHashVShare,
			FindCredentialPedersenCommit: findCredentialProtoPC,
		}

		bulkCredentials[i] = &bulkCredential
	}

	var pwalletAddr sdk.AccAddress
	pwalletAddr, err = sdk.AccAddressFromBech32(provider.WalletAddr)
	if err != nil {
		fmt.Println("couldn't convert to addr", provider.WalletAddr, err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientCtx := ClientCtx.WithFrom(provider.WalletID).WithFromAddress(pwalletAddr).WithFromName(provider.Name)

	bulkVShareBind := c.MarshalAndVShareBEncryptStep3(bulkVShare)
	bulkHashVShareBind := c.MarshalAndVShareBEncryptStep3(bulkHashVShare)

	// check bind
	// compute hash of vshare encrypted data in bulkCredentials

	bulkVShareHash := sha256.New()
	for _, bulkCredential := range bulkCredentials {
		bulkVShareHash.Write(bulkCredential.EncCredentialInfoVShare)
	}
	// get hash
	bulkVShareHashed := bulkVShareHash.Sum(nil)

	// print hashed
	fmt.Println("bulkVShare hashed", hex.EncodeToString(bulkVShareHashed))

	bulkHashVShareHash := sha256.New()
	for _, bulkCredential := range bulkCredentials {
		bulkHashVShareHash.Write(bulkCredential.EncCredentialInfoVShare)
	}
	// get hash
	bulkHashVShareHashed := bulkHashVShareHash.Sum(nil)

	// print hashed
	fmt.Println("bulkHashVShare hashed", hex.EncodeToString(bulkHashVShareHashed))

	if bulkVShareBind.VShareBVerify(bulkVShareHashed) && bulkHashVShareBind.VShareBVerify(bulkHashVShareHashed) {
		fmt.Println("bulkVShare bind verified")
		fmt.Println("bulkHashVShare bind verified")

		// decrypt
		var pp types.EncryptablePersonalInfo
		err = c.VShareBDecryptAndProtoUnmarshal(provider.PrivK, provider.PubK, bulkVShareBind, bulkCredentials[0].EncCredentialInfoVShare, &pp)
		if err != nil {
			fmt.Println("error decrypting", err)
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// print pp
		fmt.Println("pp", c.PrettyPrint(pp))
	} else {
		fmt.Println("bind not verified")
		context.JSON(http.StatusBadRequest, gin.H{"error": "bind not verified"})
		return
	}

	// create the "protoized" bind data
	protoBulkVShareBind := c.ProtoizeVShareBindData(bulkVShareBind)
	protoBulkHashVShareBind := c.ProtoizeVShareBindData(bulkHashVShareBind)

	msgs := make([]sdk.Msg, 1)

	msg := types.NewMsgCreateBulkCredentials(provider.WalletAddr,
		types.PersonalInfoCredentialType,
		protoBulkVShareBind,
		protoBulkHashVShareBind,
		s.privateEnclaveParams.EKYCWalletID,
		bulkCredentials)

	msgs[0] = msg

	fmt.Println("msgs", c.PrettyPrint(msgs))

	flagSet := RootCmd.Flags()

	var gasPerCredential int64 = 110000000000000
	gas := strconv.FormatInt(gasPerCredential*int64(len(bulkCredentials)), 10)
	flagSet.Set(flags.FlagGas, gas)

	gas, err = flagSet.GetString(flags.FlagGas)
	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("flags.FlagGas", gas)

	flagSet.Set(flags.FlagGasPrices, "100000aqdn")

	gasPrice, err := flagSet.GetString(flags.FlagGasPrices)
	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("flags.FlagGasPrices", gasPrice)

	if printTxSize {
		// check how big the tx is, using BuildSimTx

		txf, err := qadenatx.NewFactoryCLI(clientCtx, flagSet)

		if err != nil {
			fmt.Println("got error", err)
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		tx, err := txf.BuildSimTx(msgs...)

		if err != nil {
			fmt.Println("got error", err)
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// print size of tx
		fmt.Println("tx size", len(tx))
	}

	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "bulk create credential", msgs...)

	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	context.JSON(http.StatusOK, BulkSubmitKYCResponse{Status: "ok"})
}

// func to create and broadcast a MsgCreateCredential, it will do what's right with the gin.Context; this is expected to be called from submitKYC
func (s *EKycServer) createPersonalInfoCreateCredentialMsg(provider *Provider, findCredentialPC *c.PedersenCommit, p *types.EncryptablePersonalInfo, referenceCredentialID string, pin *big.Int, ssIntervalPubKID string, ssIntervalPubK string) (msg *types.MsgCreateCredential, err error) {
	var credentialHash string
	firstMiddleLast := p.Details.LastName + "," + p.Details.MiddleName + "," + p.Details.FirstName

	credentialHash = c.Hash(firstMiddleLast)

	// CREATE ALL PERSONAL-INFO

	all, err := proto.Marshal(p.Details)

	if err != nil {
		return
	}

	// note that the pin is not included in the hash for credentialPC

	if all == nil {
		err = errors.New("invalid data, couldn't convert to json")
		return
	}

	credentialPC := c.NewPedersenCommit(big.NewInt(0).SetBytes(tmhash.Sum(all)), pin)

	credWalletID := provider.WalletID + "-" + strconv.FormatInt(time.Now().UnixMilli(), 16)

	fmt.Println("credWalletID", credWalletID)

	// nodes who will be cc'd for the vshare
	ccPubK := []c.VSharePubKInfo{
		c.VSharePubKInfo{PubK: provider.PubK, NodeID: "", NodeType: ""},
		c.VSharePubKInfo{PubK: ssIntervalPubKID, NodeID: types.SSNodeID, NodeType: types.SSNodeType},
	}

	// add the pin when encrypting
	encCredentialInfoVShare, credentialInfoVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, p)

	// print size of encCredentialInfoVShare
	fmt.Println("encCredentialInfoVShare size", len(encCredentialInfoVShare))

	encCredentialHashVShare, credentialHashVShareBind := c.ProtoMarshalAndVShareBEncrypt(ccPubK, &types.EncryptableString{Value: credentialHash})

	// print size of encCredentialInfoVShare
	fmt.Println("encCredentialHashVShare size", len(encCredentialHashVShare))

	if c.DebugAmounts {
	} else {
		credentialPC.A = c.BigIntZero
		credentialPC.X = c.BigIntZero
	}

	findCredentialProtoPC := c.ProtoizeBPedersenCommit(findCredentialPC)
	credentialProtoPC := c.ProtoizeBPedersenCommit(credentialPC)

	// create the "protoized" bind data
	protoCredentialInfoVShareBind := c.ProtoizeVShareBindData(credentialInfoVShareBind)
	protoCredentialHashVShareBind := c.ProtoizeVShareBindData(credentialHashVShareBind)

	msg = types.NewMsgCreateCredential(
		provider.WalletAddr,
		credWalletID,
		types.PersonalInfoCredentialType,
		credentialProtoPC,
		protoCredentialInfoVShareBind,
		encCredentialInfoVShare,
		protoCredentialHashVShareBind,
		encCredentialHashVShare,
		findCredentialProtoPC,
		s.privateEnclaveParams.EKYCWalletID,
		referenceCredentialID,
	)

	return
}

// func to create and broadcast a MsgCreateCredential, it will do what's right with the gin.Context; this is expected to be called from submitKYC
func (s *EKycServer) broadcastMsgs(provider *Provider, msgs []sdk.Msg) bool {
	var pwalletAddr sdk.AccAddress
	var err error
	pwalletAddr, err = sdk.AccAddressFromBech32(provider.WalletAddr)
	if err != nil {
		fmt.Println("couldn't convert to addr", provider.WalletAddr, err)
		return false
	}

	clientCtx := ClientCtx.WithFrom(provider.WalletID).WithFromAddress(pwalletAddr).WithFromName(provider.Name)

	fmt.Println("msgs", c.PrettyPrint(msgs))

	flagSet := RootCmd.Flags()

	var gasPerCredential int64 = 110000000000000
	gas := strconv.FormatInt(gasPerCredential*int64(len(msgs)), 10)
	flagSet.Set(flags.FlagGas, gas)

	gas, err = flagSet.GetString(flags.FlagGas)
	if err != nil {
		fmt.Println("got error", err)
		return false
	}
	fmt.Println("flags.FlagGas", gas)

	flagSet.Set(flags.FlagGasPrices, "100000aqdn")

	gasPrice, err := flagSet.GetString(flags.FlagGasPrices)
	if err != nil {
		fmt.Println("got error", err)
		return false
	}
	fmt.Println("flags.FlagGasPrices", gasPrice)

	if printTxSize {
		// check how big the tx is, using BuildSimTx

		txf, err := qadenatx.NewFactoryCLI(clientCtx, flagSet)
		if err != nil {
			fmt.Println("got error", err)
			return false
		}

		tx, err := txf.BuildSimTx(msgs...)

		if err != nil {
			fmt.Println("got error", err)
			return false
		}

		// print size of tx
		fmt.Println("tx size", len(tx))
	}

	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "create credential", msgs...)

	if err != nil {
		fmt.Println("got error", err)
		return false
	}

	return true
}

// func to create and broadcast a MsgCreateCredential, it will do what's right with the gin.Context; this is expected to be called from submitKYC
func (s *EKycServer) createAndBroadcastPersonalInfoCreateCredentialMsg(context *gin.Context, provider *Provider, findCredentialPC *c.PedersenCommit, p *types.EncryptablePersonalInfo, referenceCredentialID string) bool {

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))

	ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ClientCtx, types.SSNodeID, types.SSNodeType)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	fmt.Println("ssIntervalPubKID", ssIntervalPubKID, "ssIntervalPubK", ssIntervalPubK)

	msg, err := s.createPersonalInfoCreateCredentialMsg(provider, findCredentialPC, p, referenceCredentialID, pin, ssIntervalPubKID, ssIntervalPubK)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}

	var pwalletAddr sdk.AccAddress
	pwalletAddr, err = sdk.AccAddressFromBech32(provider.WalletAddr)
	if err != nil {
		fmt.Println("couldn't convert to addr", provider.WalletAddr, err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}

	clientCtx := ClientCtx.WithFrom(provider.WalletID).WithFromAddress(pwalletAddr).WithFromName(provider.Name)

	if err := msg.ValidateBasic(); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}

	msgs := make([]sdk.Msg, 1)
	msgs[0] = msg

	fmt.Println("msgs", c.PrettyPrint(msgs))

	flagSet := RootCmd.Flags()

	flagSet.Set(flags.FlagGas, "110000000000000")

	gas, err := flagSet.GetString(flags.FlagGas)
	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	fmt.Println("flags.FlagGas", gas)

	flagSet.Set(flags.FlagGasPrices, "100000aqdn")

	gasPrice, err := flagSet.GetString(flags.FlagGasPrices)
	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}
	fmt.Println("flags.FlagGasPrices", gasPrice)

	if printTxSize {
		// check how big the tx is, using BuildSimTx

		txf, err := qadenatx.NewFactoryCLI(clientCtx, flagSet)
		if err != nil {
			fmt.Println("got error", err)
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return false
		}

		tx, err := txf.BuildSimTx(msgs...)

		if err != nil {
			fmt.Println("got error", err)
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return false
		}

		// print size of tx
		fmt.Println("tx size", len(tx))
	}

	err, _ = qadenatx.GenerateOrBroadcastTxCLISync(clientCtx, flagSet, "create credential", msgs...)

	if err != nil {
		fmt.Println("got error", err)
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return false
	}

	context.JSON(http.StatusOK, SubmitKYCResponse{CredentialAddress: msg.CredentialID, PersonalInfoDetails: *p.Details, Logo: provider.Logo})
	return true
}

// implement gin post method for registerProvider
func (s *EKycServer) registerKYCProvider(context *gin.Context) {
	var registerKYCProviderRequest RegisterKYCProviderRequest
	if err := context.ShouldBindJSON(&registerKYCProviderRequest); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "registerKYCProviderRequest "+c.PrettyPrint(registerKYCProviderRequest))
	// add the provider to the list of providers
	// create new Provider

	kb := ClientCtx.Keyring

	// print ArmorPrivKey
	c.LoggerDebug(logger, "ArmorPrivKey "+registerKYCProviderRequest.ArmorPrivKey)

	err := kb.ImportPrivKey(registerKYCProviderRequest.Name, registerKYCProviderRequest.ArmorPrivKey, registerKYCProviderRequest.ArmorPassPhrase)

	if err != nil {
		c.LoggerError(logger, "couldn't import privk "+err.Error())
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var provider Provider

	var pwalletAddr sdk.AccAddress

	provider.Name = registerKYCProviderRequest.Name
	provider.FriendlyName = registerKYCProviderRequest.FriendlyName
	provider.Logo = registerKYCProviderRequest.Logo

	provider.WalletID, pwalletAddr, provider.PubK, provider.PrivK, provider.ArmorPrivK, err = c.GetAddressByName(ClientCtx, registerKYCProviderRequest.Name, ArmorPassPhrase)
	if err != nil {
		c.LoggerError(logger, "couldn't get address for "+registerKYCProviderRequest.FriendlyName+" "+err.Error())
		return

	}

	provider.WalletAddr = pwalletAddr.String()

	// check if the provider already exists
	if s.findProvider(provider.Name) != nil {
		c.LoggerError(logger, "provider "+provider.Name+" already exists")
		context.JSON(http.StatusBadRequest, gin.H{"error": "provider " + provider.Name + " already exists"})
		return
	}

	s.privateEnclaveParams.Providers = append(s.privateEnclaveParams.Providers, provider)

	context.JSON(http.StatusOK, gin.H{"status": "ok"})

	s.saveEnclaveParams()
}

// V2 API

// implement gin post method for beginKYC
func (s *EKycServer) beginKYC(context *gin.Context) {
	var request BeginKYCRequest
	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "KYC "+c.PrettyPrint(request))

	// find the provider
	var provider *Provider = s.findProvider(request.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	phoneNumber := strings.TrimSpace(strings.ToLower(request.PhoneNumber))

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationParams{}
		params.SetTo(phoneNumber)
		params.SetChannel("sms")

		resp, err := client.VerifyV2.CreateVerification(TwilioVerificationService, params)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			fmt.Println(err.Error())
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
			} else {
				fmt.Println(resp.Status)
			}
		}
	}

	sessionID := BeginKYCSessionID{
		ProviderName: request.ProviderName,
		PhoneNumber:  phoneNumber,
	}

	// encrypt sessionID with provider pubk

	encSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, sessionID)

	context.JSON(http.StatusOK, BeginKYCResponse{SessionID: encSessionID})
}

// findProvider given name
func (s *EKycServer) findProvider(name string) *Provider {
	for _, p := range s.privateEnclaveParams.Providers {
		if p.Name == name {
			return &p
		}
	}
	return nil
}

// authenticateOTP
func (s *EKycServer) authenticateOTP(context *gin.Context) {
	var request AuthenticateOTPRequest

	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "authenticateOTPRequest "+c.PrettyPrint(request))

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID BeginKYCSessionID

	sessid := request.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationCheckParams{}
		params.SetTo(sessionID.PhoneNumber)
		params.SetCode(request.OTP)

		resp, err := client.VerifyV2.CreateVerificationCheck(TwilioVerificationService, params)
		if err != nil {
			fmt.Println(err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
				if *resp.Status == "pending" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
					return
				} else if *resp.Status != "approved" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "bad status"})
					return
				}
				fmt.Println("approved")
			} else {
				fmt.Println(resp.Status)
				context.JSON(http.StatusBadRequest, gin.H{"error": "nil status"})
				return
			}
		}

	} else {
		if request.OTP != "111111" {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
			return
		}
	}

	c.LoggerDebug(logger, "authenticated OTP")

	// good path, passed the OTP stage
	context.JSON(http.StatusOK, gin.H{"error": ""})
}

// authenticateKYC
func (s *EKycServer) authenticateKYC(context *gin.Context) {
	// print the request body

	/*
		body, _ := ioutil.ReadAll(context.Request.Body)
		c.LoggerDebug(logger, "authenticateKYCRequest body", string(body))
	*/

	var request AuthenticateKYCRequest

	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "authenticateKYCRequest "+c.PrettyPrint(request))

	// decrypt submitUserVerificationRequest.EncSessionID
	var sessionID BeginKYCSessionID

	sessid := request.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(request.LastName))

	// find the provider
	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	if sendTwilio {
		client := twilio.NewRestClientWithParams(twilio.ClientParams{
			Username: TwilioAccountSid,
			Password: TwilioAuthToken,
		})

		params := &verify.CreateVerificationCheckParams{}
		params.SetTo(sessionID.PhoneNumber)
		params.SetCode(request.OTP)

		resp, err := client.VerifyV2.CreateVerificationCheck(TwilioVerificationService, params)
		if err != nil {
			fmt.Println(err.Error())
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		} else {
			if resp.Status != nil {
				fmt.Println(*resp.Status)
				if *resp.Status == "pending" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
					return
				} else if *resp.Status != "approved" {
					context.JSON(http.StatusBadRequest, gin.H{"error": "bad status"})
					return
				}
				fmt.Println("approved")
			} else {
				fmt.Println(resp.Status)
				context.JSON(http.StatusBadRequest, gin.H{"error": "nil status"})
				return
			}
		}

	} else {
		if request.OTP != "111111" {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Invalid OTP"})
			return
		}
	}

	// good path, passed the OTP stage

	var newSessionID AuthenticateKYCSessionID
	newSessionID.FromProviderName = request.FromProviderName
	newSessionID.ProviderName = sessionID.ProviderName
	newSessionID.PhoneNumber = sessionID.PhoneNumber

	var personalInfo types.EncryptablePersonalInfo
	var referenceCredentialID string //	var credentialID string

	// check if provider already has a credential for this user
	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + sessionID.PhoneNumber)))
	findCredentialPC := c.NewPedersenCommit(all, pin)

	exists, err := s.queryFindCredential(provider, *findCredentialPC, &personalInfo, &referenceCredentialID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		c.LoggerDebug(logger, "credential exists for the requesting provider", sessionID.ProviderName)
		newSessionID.PersonalInfo = personalInfo
		newSessionID.ReferenceCredentialID = referenceCredentialID
		newSessionID.FromProviderName = sessionID.ProviderName
		newSessionID.Reusable = true
		encNewSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, newSessionID)
		if c.TextBasedEncrypt {
			encNewSessionID = hex.EncodeToString([]byte(encNewSessionID))
		}
		context.JSON(http.StatusOK, AuthenticateKYCResponse{SessionID: encNewSessionID, Reusable: true, FromProviderName: sessionID.ProviderName, PersonalInfo: personalInfo})
		return
	}

	// find the fromProvider
	var fromProvider *Provider

	if request.FromProviderName == "" {
		// requester didn't care who the fromProviderName is, let's find it
		for _, p := range s.privateEnclaveParams.Providers {
			if p.Name != sessionID.ProviderName {
				pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(p.PrivK)))
				all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + sessionID.PhoneNumber)))
				fromProviderFindCredentialPC := c.NewPedersenCommit(all, pin)

				exists, err = s.queryFindCredential(&p, *fromProviderFindCredentialPC, &personalInfo, &referenceCredentialID)

				if err != nil {
					context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
					return
				}
				if exists {
					fromProvider = &p
					newSessionID.FromProviderName = fromProvider.Name
					c.LoggerDebug(logger, "Found credential under provider", fromProvider.Name)
					break
				}
			}
		}
	} else {
		fromProvider = s.findProvider(request.FromProviderName)
		if fromProvider == nil {
			// search for a provider
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid fromProvider"})
			return
		}
		pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(fromProvider.PrivK)))
		all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + sessionID.PhoneNumber)))
		fromProviderFindCredentialPC := c.NewPedersenCommit(all, pin)

		exists, err = s.queryFindCredential(fromProvider, *fromProviderFindCredentialPC, &personalInfo, &referenceCredentialID)

		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
	}

	if !exists {
		newSessionID.Reusable = false
		encNewSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, newSessionID)
		if c.TextBasedEncrypt {
			encNewSessionID = hex.EncodeToString([]byte(encNewSessionID))
		}
		context.JSON(http.StatusOK, AuthenticateKYCResponse{SessionID: encNewSessionID, Reusable: false})
		return
	} else {
		newSessionID.Reusable = true
		newSessionID.PersonalInfo = personalInfo
		newSessionID.ReferenceCredentialID = referenceCredentialID

		encNewSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, newSessionID)
		if c.TextBasedEncrypt {
			encNewSessionID = hex.EncodeToString([]byte(encNewSessionID))
		}
		context.JSON(http.StatusOK, AuthenticateKYCResponse{SessionID: encNewSessionID, Reusable: true, FromProviderName: fromProvider.Name, PersonalInfo: personalInfo})
	}
}

// webhook
func (s *EKycServer) webhookSubmitKYC(context *gin.Context) {
	// print the request body

	body, err := ioutil.ReadAll(context.Request.Body)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Print the request body
	c.LoggerDebug(logger, "webhookSubmitKYC body "+string(body))

	// respond ok
	context.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// Define the struct that matches the JSON structure
type AdvaiStartTransactionResponse struct {
	Code            string                    `json:"code"`
	Message         string                    `json:"message"`
	Data            AdvaiStartTransactionData `json:"data"`
	Extra           interface{}               `json:"extra"` // Use `interface{}` if it's sometimes null or dynamic
	TransactionID   string                    `json:"transactionId"`
	PricingStrategy string                    `json:"pricingStrategy"`
}

type AdvaiStartTransactionData struct {
	SdkToken    string                           `json:"sdkToken"`
	TransID     string                           `json:"transId"`
	H5Url       string                           `json:"h5Url"`
	OriginInput AdvaiStartTransactionOriginInput `json:"originInput"`
}

type AdvaiStartTransactionOriginInput struct {
	SessionID string `json:"session_id"`
}
type AdvaiRetrieveAnInquiryResponse struct {
	Code            string                     `json:"code"`
	Message         string                     `json:"message"`
	Data            AdvaiRetrieveAnInquiryData `json:"data"`
	TransactionID   string                     `json:"transactionId"`
	Datetime        float64                    `json:"datetime"`
	Extra           *string                    `json:"extra"`
	PricingStrategy string                     `json:"pricingStrategy"`
	Timestamp       int64                      `json:"timestamp"`
}

type AdvaiRetrieveAnInquiryData struct {
	ID              string                                `json:"id"`
	BaseInformation AdvaiRetrieveAnInquiryBaseInformation `json:"baseInfomation"`
	Relationships   AdvaiRetrieveAnInquiryRelationships   `json:"relationShips"`
	Nodes           []AdvaiRetrieveAnInquiryNode          `json:"nodes"`
}

type AdvaiRetrieveAnInquiryBaseInformation struct {
	ReferenceID *string `json:"referenceId"`
	CreatedAt   string  `json:"createAt"`
	UpdatedAt   string  `json:"updateAt"`
	Status      string  `json:"status"`
	Result      string  `json:"result"`
}

type AdvaiRetrieveAnInquiryRelationships struct {
	Workflow        AdvaiRetrieveAnInquiryWorkflow `json:"workflow"`
	CustomerProfile *string                        `json:"customerProfile"`
}

type AdvaiRetrieveAnInquiryWorkflow struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type AdvaiRetrieveAnInquiryNode struct {
	Type                  string                                    `json:"type"`
	Name                  string                                    `json:"name"`
	ID                    int                                       `json:"id"`
	Code                  string                                    `json:"code"`
	Message               *string                                   `json:"message"`
	StartedAt             string                                    `json:"startedAt"`
	CompletedAt           string                                    `json:"completedAt"`
	Attributes            *[]AdvaiRetrieveAnInquiryAttribute        `json:"attributes,omitempty"`
	Result                *AdvaiRetrieveAnInquiryResult             `json:"result"`
	VerificationResult    string                                    `json:"verificationResult"`
	AttemptSubNodeDTOList []AdvaiRetrieveAnInquiryAttemptSubNodeDTO `json:"attemptSubNodeDTOList,omitempty"`
	AttemptCount          *int                                      `json:"attemptCount,omitempty"`
}

type AdvaiRetrieveAnInquiryAttribute struct {
	VariableName  string `json:"variableName"`
	VariableType  string `json:"variableType"`
	VariableValue string `json:"variableValue"`
}

type AdvaiRetrieveAnInquiryAttemptSubNodeDTO struct {
	Input     AdvaiRetrieveAnInquiryInput     `json:"input"`
	OCR       AdvaiRetrieveAnInquiryOCR       `json:"ocr"`
	IDForgery AdvaiRetrieveAnInquiryIDForgery `json:"idForgery"`
}

type AdvaiRetrieveAnInquiryInput struct {
	Region    string  `json:"region"`
	CardType  string  `json:"cardType"`
	FrontFile string  `json:"frontFile"`
	BackFile  *string `json:"backFile"`
}

type AdvaiRetrieveAnInquiryOCR struct {
	Front                  Front                  `json:"front"`
	Back                   *string                `json:"back"`
	CrossCheck             map[string]string      `json:"crossCheck"`
	AgeVerification        AgeVerification        `json:"ageVerification"`
	ExpiryDateVerification ExpiryDateVerification `json:"expiryDateVerification"`
}

type AdvaiRetrieveAnInquiryFront struct {
	Side         string            `json:"side"`
	Gender       string            `json:"gender"`
	Height       string            `json:"height"`
	Weight       string            `json:"weight"`
	Birthday     string            `json:"birthday"`
	EyeColor     string            `json:"eyeColor"`
	FullName     string            `json:"fullName"`
	IDNumber     string            `json:"idNumber"`
	BloodType    string            `json:"bloodType"`
	ExpiryDate   string            `json:"expiryDate"`
	FullAddress  string            `json:"fullAddress"`
	Nationality  string            `json:"nationality"`
	Restrictions string            `json:"restrictions"`
	Others       map[string]string `json:"others"`
}

type AdvaiRetrieveAnInquiryAgeVerification struct {
	Age    int    `json:"age"`
	Result string `json:"result"`
}

type AdvaiRetrieveAnInquiryExpiryDateVerification struct {
	Result       string `json:"result"`
	DaysToExpiry int    `json:"daysToExpiry"`
}

type AdvaiRetrieveAnInquiryIDForgery struct {
	Result     string   `json:"result"`
	FailReason []string `json:"failReason"`
}

type AdvaiRetrieveAnInquiryResult struct {
	Attempts []AdvaiRetrieveAnInquirySelfieAttempt `json:"attempts"`
}

type AdvaiRetrieveAnInquirySelfieAttempt struct {
	AttemptResult  bool                                 `json:"attemptResult"`
	Liveness3D     AdvaiRetrieveAnInquiryLiveness3D     `json:"liveness3d"`
	FaceComparison AdvaiRetrieveAnInquiryFaceComparison `json:"faceComparison"`
}

type AdvaiRetrieveAnInquiryLiveness3D struct {
	CheckResult        bool    `json:"checkResult"`
	ErrorMessage       *string `json:"errorMessage"`
	StartTime          string  `json:"startTime"`
	EndTime            string  `json:"endTime"`
	FaceImageUrl       string  `json:"faceImageUrl"`
	LivenessCheck      bool    `json:"livenessCheck"`
	SelfieCheck        bool    `json:"selfieCheck"`
	ReplayAttackCheck  bool    `json:"replayAttackCheck"`
	SessionAttackCheck bool    `json:"sessionAttackCheck"`
}

type AdvaiRetrieveAnInquiryFaceComparison struct {
	CheckResult   bool                           `json:"checkResult"`
	ErrorMessage  *string                        `json:"errorMessage"`
	StartTime     string                         `json:"startTime"`
	EndTime       string                         `json:"endTime"`
	Code          string                         `json:"code"`
	Data          AdvaiRetrieveAnInquiryFaceData `json:"data"`
	TransactionID string                         `json:"transactionId"`
	FacePhotoUri  string                         `json:"facePhotoUri"`
	IDPhotoUri    string                         `json:"idPhotoUri"`
	Similarity    string                         `json:"similarity"`
}

type AdvaiRetrieveAnInquiryFaceData struct {
	FirstFace  AdvaiRetrieveAnInquiryFaceDetails `json:"firstFace"`
	SecondFace AdvaiRetrieveAnInquiryFaceDetails `json:"secondFace"`
}

type AdvaiRetrieveAnInquiryFaceDetails struct {
	ID     string `json:"id"`
	Top    string `json:"top"`
	Left   string `json:"left"`
	Right  string `json:"right"`
	Bottom string `json:"bottom"`
}

// statusKYC

func (s *EKycServer) statusKYC(context *gin.Context) {
	// get the refernceID from URL params

	referenceID := context.Param("referenceID")

	// get the sessionID
	confirmNewKYCSessionIDJSON, ok := sessionStore.Get(referenceID)

	if !ok {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid referenceID"})
		return
	}

	// parse JSON
	var confirmNewKYCSessionID ConfirmNewKYCSessionID

	err := json.Unmarshal([]byte(confirmNewKYCSessionIDJSON), &confirmNewKYCSessionID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the sessionID
	c.LoggerDebug(logger, "statusKYC sessionID JSON "+confirmNewKYCSessionIDJSON)

	// call Advai to get the status

	httpgeturl := AdvaiRetrieveAnInquiryURL + "?" + "transactionId=" + referenceID

	// create the http request
	advairequest, err := http.NewRequest("GET", httpgeturl, nil)
	if err != nil {
		return
	}

	// set the request header
	advairequest.Header.Set("Content-Type", "application/json")
	advairequest.Header.Set("x-advai-key", AdvanceAIAccessKey)

	// create the http client
	client := &http.Client{}

	// send the request
	response, err := client.Do(advairequest)
	if err != nil {
		return
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Print the request body
	c.LoggerDebug(logger, "body "+string(body))

	// close the response body
	defer response.Body.Close()

	// parse the body
	var advaiRetrieveAnInquiryResponse AdvaiRetrieveAnInquiryResponse

	err = json.Unmarshal(body, &advaiRetrieveAnInquiryResponse)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if advaiRetrieveAnInquiryResponse.Code != "SUCCESS" {
		context.JSON(http.StatusBadRequest, gin.H{"error": advaiRetrieveAnInquiryResponse.Message})
		return
	}

	// create personalinfoDetails
	var pd types.EncryptablePersonalInfoDetails

	hasKYC := false

	for _, node := range advaiRetrieveAnInquiryResponse.Data.Nodes {
		if node.Type == "Document Verification" && len(node.AttemptSubNodeDTOList) > 0 {
			// iterate through the attemptSubNodeDTOList
			for _, attemptSubNodeDTO := range node.AttemptSubNodeDTOList {
				if attemptSubNodeDTO.Input.CardType == "DRIVING_LICENSE" {
					front := attemptSubNodeDTO.OCR.Front
					fmt.Println("Birthday:", front.Birthday)
					fmt.Println("Gender:", front.Gender)
					fmt.Println("Full Name:", front.FullName)
					fmt.Println("Nationality:", front.Nationality)

					var parsedFullName fullname_parser.ParsedName
					parsedFullName = fullname_parser.ParseFullname(*front.FullName)

					var firstName string
					var lastName string
					var middleName string

					if parsedFullName.First != "" {
						firstName = parsedFullName.First
						lastName = parsedFullName.Last
						middleName = parsedFullName.Middle
					} else {
						context.JSON(http.StatusBadRequest, gin.H{"error": "couldn't parse full name"})
						return
					}

					pd.FirstName = strings.ToLower(firstName)
					pd.LastName = strings.ToLower(lastName)
					pd.MiddleName = strings.ToLower(middleName)

					// parse birthdate format mm/dd/yyyy
					t, err := time.Parse("2006/01/02", *front.Birthday)

					if err != nil {
						context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
						return
					}

					const shortForm = "2006-Jan-02"
					pd.Birthdate = t.Format(shortForm)

					pd.Gender = types.NormalizeGender(*front.Gender)

					// do the gountries
					// normalize nationality using gountries

					query := gountries.New()

					countries := strings.Split(*front.Nationality, ",")

					normalizedCountries := make([]string, len(countries))
					for i := range countries {
						var country gountries.Country
						country, err = query.FindCountryByAlpha(countries[i])
						if err != nil {
							country, err = query.FindCountryByName(countries[i])
							if err != nil {
								country, err = query.FindCountryByNativeName(countries[i])
								if err != nil {
									return
								}
							}
						}

						normalizedCountries[i] = country.Alpha2
					}

					pd.Citizenship = strings.Join(normalizedCountries, ",")
					pd.Residency = pd.Citizenship

					hasKYC = true

					break
				}
			}
		}
	}

	if !hasKYC {
		context.JSON(http.StatusBadRequest, gin.H{"error": "couldn't find KYC"})
		return
	}

	// parse confirmNewKYCSessionID.AuthenticateKYCSessionID
	var authenticateKYCSessionID AuthenticateKYCSessionID

	_, err = c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, confirmNewKYCSessionID.AuthenticateKYCSessionID, &authenticateKYCSessionID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var newSessionID SubmittedKYCSessionID

	newSessionID.PersonalInfoDetails = pd
	newSessionID.ProviderName = authenticateKYCSessionID.ProviderName
	newSessionID.PhoneNumber = authenticateKYCSessionID.PhoneNumber

	// encrypt newSessionID
	encNewSessionID := c.MarshalAndEncrypt(s.privateEnclaveParams.EKYCPubK, newSessionID)

	if c.TextBasedEncrypt {
		encNewSessionID = hex.EncodeToString([]byte(encNewSessionID))
	}

	// return
	var statusKYCResponse StatusKYCResponse

	statusKYCResponse.SessionID = encNewSessionID
	statusKYCResponse.PersonalInfoDetails = pd
	statusKYCResponse.PhoneNumber = authenticateKYCSessionID.PhoneNumber

	context.JSON(http.StatusOK, statusKYCResponse)
}

// implement gin post method for submitNewKYCv2
func (s *EKycServer) submitNewKYCv2(context *gin.Context) {
	var submitNewKYCv2Request SubmitNewKYCv2Request
	if err := context.ShouldBindJSON(&submitNewKYCv2Request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "submitNewKYCv2Request "+c.PrettyPrint(submitNewKYCv2Request))

	// decrypt submitNewKYCv2Request.SessionID

	var sessionID SubmittedKYCSessionID

	sessid := submitNewKYCv2Request.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	// check if there is no change in the personal info
	origFirstMiddleLast := strings.ToLower(sessionID.PersonalInfoDetails.FirstName + sessionID.PersonalInfoDetails.MiddleName + sessionID.PersonalInfoDetails.LastName)
	origFirstMiddleLast = strings.ReplaceAll(origFirstMiddleLast, " ", "")
	newFirstMiddleLast := strings.ToLower(submitNewKYCv2Request.FirstName + submitNewKYCv2Request.MiddleName + sessionID.PersonalInfoDetails.LastName)
	newFirstMiddleLast = strings.ReplaceAll(newFirstMiddleLast, " ", "")

	if origFirstMiddleLast == "" {
		context.JSON(http.StatusBadRequest, gin.H{"error": "original personal info is empty"})
		return
	}

	if origFirstMiddleLast != newFirstMiddleLast {
		context.JSON(http.StatusBadRequest, gin.H{"error": "personal info doesn't match [" + origFirstMiddleLast + "] [" + newFirstMiddleLast + "]"})
		return
	}

	lastName := strings.TrimSpace(strings.ToLower(sessionID.PersonalInfoDetails.LastName))
	middleName := strings.TrimSpace(strings.ToLower(submitNewKYCv2Request.MiddleName))
	firstName := strings.TrimSpace(strings.ToLower(submitNewKYCv2Request.FirstName))
	phoneNumber := strings.TrimSpace(strings.ToLower(sessionID.PhoneNumber))

	pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
	all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(lastName + phoneNumber)))

	findCredentialPC := c.NewPedersenCommit(all, pin)

	// find the credential by XY to see if it already exists on the chain for this provider
	var existingP types.EncryptablePersonalInfo
	var credentialID string

	exists, err := s.queryFindCredential(provider, *findCredentialPC, &existingP, &credentialID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if exists {
		// credential already exists
		context.JSON(http.StatusBadRequest, gin.H{"error": "Credential already exists"})
		return
	}

	// we are here, so there was no previous credential, so we can create a new one, but let's use the updated personal info where necessary

	p, err := s.newPersonalInfo(submitNewKYCv2Request.PIN,
		firstName,
		middleName,
		lastName,
		sessionID.PersonalInfoDetails.Birthdate,
		sessionID.PersonalInfoDetails.Citizenship,
		sessionID.PersonalInfoDetails.Residency,
		sessionID.PersonalInfoDetails.Gender)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.createAndBroadcastPersonalInfoCreateCredentialMsg(context, provider, findCredentialPC, p, "")
}

func (s *EKycServer) collectNewKYC(context *gin.Context) {
	// get the referenceID from URL params

	referenceID := context.Param("referenceID")

	// get the sessionID
	confirmNewKYCSessionIDJSON, ok := sessionStore.Get(referenceID)

	if !ok {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid referenceID"})
		return
		//		sessionID = "1234567890"
	}

	// parse JSON
	var confirmNewKYCSessionID ConfirmNewKYCSessionID

	err := json.Unmarshal([]byte(confirmNewKYCSessionIDJSON), &confirmNewKYCSessionID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// print the sessionID
	c.LoggerDebug(logger, "collectNewKYC sessionID JSON "+confirmNewKYCSessionIDJSON)

	// Use fmt.Sprintf to inject the URL into the HTML content
	htmlContent := fmt.Sprintf(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>eKYC.ph Identity Checker</title>
  <style>
    /* Center the iframe in the viewport */
    .iphone-container {
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;  /* Full height of the viewport */
      background-color: #f7f7f7;
    }

    /* Portrait mode iPhone-like iframe */
    .iphone-iframe {
      width: 390px;   /* Portrait width */
      height: 675px;  /* Portrait height */
      border: 1px solid #ccc;
      box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.1); /* Shadow for device look */
      border-radius: 20px; /* Rounded corners like an iPhone */
    }
  </style>
  <script>
    // Listen for messages sent to this window
    window.onmessage = e => {
      // Display an alert with the received message data
      console.log('WINDOW ONMESSAGE Received message:', e.data);

	  // Check if e.data.type is "hookEvent" and e.data.payload.type is "complete"
		if (e.data.type === "hookEvent" && e.data.payload.type === "complete") {
			// Extract the type, status, and transId
			const type = e.data.payload.type;         // e.g., "complete"
			const status = e.data.payload.data.status;  // e.g., "FAILED"
			const transId = e.data.payload.data.transId;  // e.g., "ae1977ad02865928"

			// Construct the deep link with query parameters
			const deeplink = 'ekyc://ekyc.ph/checkIdentityStatus?type=' + encodeURIComponent(type) + '&status=' + encodeURIComponent(status) + '&transId=' + encodeURIComponent(transId);

			// Open the deep link
			window.location.href = deeplink;
		}  
	};
  </script>
</head>
<body>

  <div class="iphone-container">
    <!-- iFrame with iPhone dimensions (portrait mode) -->
    <iframe class="iphone-iframe" src="%s" frameborder="0" allow="microphone;camera" allowfullscreen></iframe>
  </div>

</body>
</html>
	`, confirmNewKYCSessionID.AdvaiH5URL+"&&isUseIframe=true")

	c.LoggerDebug(logger, "htmlContent "+htmlContent)

	context.Header("Content-Type", "text/html")
	context.Data(http.StatusOK, "text/html; charset=utf-8", []byte(htmlContent))
}

// confirmNewKYC
func (s *EKycServer) confirmNewKYC(context *gin.Context) {
	var request ConfirmNewKYCRequest

	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "ConfirmNewKYCRequest "+c.PrettyPrint(request))

	// decrypt
	var sessionID AuthenticateKYCSessionID

	sessid := request.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if sessionID.Reusable {
		context.JSON(http.StatusBadRequest, gin.H{"error": "ekyc is reusable"})
		return
	}

	// get the URL to be embedded in an iframe from Advai

	// call Advai to get the URL

	// create the request body
	requestBody := gin.H{
		"session_id": request.SessionID,
	}

	// convert the request body to json
	jsonValue, _ := json.Marshal(requestBody)

	// print jsonValue
	fmt.Println("jsonValue", string(jsonValue))

	httpposturl := AdvaiStartTransactionURL

	// create the http request
	advairequest, err := http.NewRequest("POST", httpposturl, bytes.NewBuffer(jsonValue))
	if err != nil {
		return
	}

	// set the request header
	advairequest.Header.Set("Content-Type", "application/json")
	advairequest.Header.Set("x-advai-key", AdvanceAIAccessKey)
	advairequest.Header.Set("journeyId", AdvanceAIJourneyID)

	// create the http client
	client := &http.Client{}

	// send the request
	response, err := client.Do(advairequest)
	if err != nil {
		return
	}

	// close the response body
	defer response.Body.Close()

	// parse the body
	var advaiStartTransactionResponse AdvaiStartTransactionResponse

	// decode the response body
	err = json.NewDecoder(response.Body).Decode(&advaiStartTransactionResponse)
	if err != nil {
		// return the error
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if advaiStartTransactionResponse.Code != "SUCCESS" {
		context.JSON(http.StatusBadRequest, gin.H{"error": advaiStartTransactionResponse.Message})
		return
	}

	// store the sessionID in a map, keyed by the transId

	// create new referenceID
	referenceID := advaiStartTransactionResponse.TransactionID

	confirmNewKYCSessionID := ConfirmNewKYCSessionID{
		AuthenticateKYCSessionID: request.SessionID,
		AdvaiH5URL:               advaiStartTransactionResponse.Data.H5Url,
	}

	// convert to json
	confirmNewKYCSessionIDJSON, err := json.Marshal(confirmNewKYCSessionID)

	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	sessionStore.Set(referenceID, string(confirmNewKYCSessionIDJSON), time.Second*1000)

	// construct the response
	var confirmNewKYCResponse ConfirmNewKYCResponse
	confirmNewKYCResponse.ReferenceID = referenceID
	confirmNewKYCResponse.URL = CollectNewKYCURL + referenceID
	confirmNewKYCResponse.Error = ""

	//return response
	context.JSON(http.StatusOK, confirmNewKYCResponse)
}

// confirmReuseKYC
func (s *EKycServer) confirmReuseKYC(context *gin.Context) {
	// print the request body

	/*
		body, _ := ioutil.ReadAll(context.Request.Body)
		c.LoggerDebug(logger, "authenticateUserReuseKYCRequest body", string(body))
	*/

	var request ConfirmReuseKYCRequest

	if err := context.ShouldBindJSON(&request); err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// print the request
	c.LoggerDebug(logger, "ConfirmReuseKYCRequest "+c.PrettyPrint(request))

	// decrypt
	var sessionID AuthenticateKYCSessionID

	sessid := request.SessionID
	// this is only when we're using DemoEncrypt
	if c.TextBasedEncrypt {
		sessidbytes, err := hex.DecodeString(sessid)

		if err != nil {
			// couldn't decode
			c.LoggerDebug(logger, "couldn't decode as hex string, using as normal string")
		} else {
			sessid = string(sessidbytes)
		}
	}
	_, err := c.DecryptAndUnmarshal(s.privateEnclaveParams.EKYCPrivK, sessid, &sessionID)
	if err != nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !sessionID.Reusable {
		context.JSON(http.StatusBadRequest, gin.H{"error": "ekyc is not reusable"})
		return
	}

	if sessionID.PersonalInfo.Details == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid sessionID"})
		return
	}

	// find the provider
	var provider *Provider = s.findProvider(sessionID.ProviderName)
	if provider == nil {
		context.JSON(http.StatusBadRequest, gin.H{"error": "invalid provider"})
		return
	}

	/*
		// find the fromProvider
		var fromProvider *Provider
		for _, p := range s.privateEnclaveParams.Providers {
			if p.Name == sessionID.FromProviderName {
				fromProvider = &p
				break
			}
		}
		if fromProvider == nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid fromProvider"})
			return
		}
	*/

	success := false
	var pin *big.Int

	if request.UserFindCredentialPedersenCommmit != "" {
		// convert to PedersenCommit
		compressed, err := hex.DecodeString(request.UserFindCredentialPedersenCommmit)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		ssIntervalPubKID, ssIntervalPubK, err := c.GetIntervalPublicKey(ClientCtx, types.SSNodeID, types.SSNodeType)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		fmt.Println("ssIntervalPubKID", ssIntervalPubKID)
		fmt.Println("ssIntervalPubK", ssIntervalPubK)

		userFindCredentialPC := c.UnprotoizeBPedersenCommit(&types.BPedersenCommit{C: &types.BECPoint{Compressed: compressed}})

		msgs := make([]sdk.Msg, 0)

		pin, success = big.NewInt(0).SetString(sessionID.PersonalInfo.PIN, 10)

		if !success {
			context.JSON(http.StatusBadRequest, gin.H{"error": "invalid pin"})
			return
		}

		msg, err := s.createPersonalInfoCreateCredentialMsg(provider, userFindCredentialPC, &sessionID.PersonalInfo, "", pin, ssIntervalPubKID, ssIntervalPubK)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		msgs = append(msgs, msg)

		msg, err = s.createSingleContactInfoCreateCredentialMsg(provider, userFindCredentialPC, &sessionID.PersonalInfo, types.FirstNamePersonalInfoCredentialType, "", pin, ssIntervalPubKID, ssIntervalPubK)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		msgs = append(msgs, msg)

		msg, err = s.createSingleContactInfoCreateCredentialMsg(provider, userFindCredentialPC, &sessionID.PersonalInfo, types.MiddleNamePersonalInfoCredentialType, "", pin, ssIntervalPubKID, ssIntervalPubK)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		msgs = append(msgs, msg)

		msg, err = s.createSingleContactInfoCreateCredentialMsg(provider, userFindCredentialPC, &sessionID.PersonalInfo, types.LastNamePersonalInfoCredentialType, "", pin, ssIntervalPubKID, ssIntervalPubK)
		if err != nil {
			context.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		msgs = append(msgs, msg)

		success = s.broadcastMsgs(provider, msgs)
	} else {
		pin := big.NewInt(0).SetBytes(tmhash.Sum([]byte(provider.PrivK)))
		all := big.NewInt(0).SetBytes(tmhash.Sum([]byte(sessionID.PersonalInfo.Details.LastName + sessionID.PhoneNumber)))

		findCredentialPC := c.NewPedersenCommit(all, pin)
		success = s.createAndBroadcastPersonalInfoCreateCredentialMsg(context, provider, findCredentialPC, &sessionID.PersonalInfo, sessionID.ReferenceCredentialID)
	}

	if !success {
		context.JSON(http.StatusBadRequest, gin.H{"error": "could not create credential"})
	}
}

func setupConfig() {
	// set the address prefixes
	config := sdk.GetConfig()
	cmdcfg.SetBech32Prefixes(config)
	// TODO fix
	// if err := cmdcfg.EnableObservability(); err != nil {
	// 	panic(err)
	// }
	cmdcfg.SetBip44CoinType(config)
	config.Seal()
}

var sessionStore *ExpirySessionStore

func main() {
	port := flag.Int("port", 80, "The API server http port")
	realEnclave := flag.Bool("realenclave", false, "Run in real enclave")
	homePath := flag.String("home", "", "Home directory")
	chainID := flag.String("chain-id", "", "Chain ID (e.g. qadena_1000-1)")
	pioneerIP := flag.String("pioneer-ip", "localhost", "PioneerIP (e.g. 192.168.86.33)")
	ekycName := flag.String("ekyc-name", "r-ekyc-app", "EKycName (e.g. r-ekyc-app)")
	armorPrivK := flag.String("ekyc-armor-privk", "", "PrivK")
	armorPassPhrase := flag.String("ekyc-armor-passphrase", "", "PassPhrase")
	flag.Parse()

	logger = c.NewTMLogger("ekyc")

	sessionStore = NewExpirySessionStore()

	c.LoggerDebug(logger, "port "+strconv.Itoa(*port))
	c.LoggerDebug(logger, "s.RealEnclave "+strconv.FormatBool(*realEnclave))
	c.LoggerDebug(logger, "homePath "+*homePath)
	c.LoggerDebug(logger, "chainID "+*chainID)
	c.LoggerDebug(logger, "pioneerIP "+*pioneerIP)

	setupConfig()
	cmdcfg.RegisterDenoms()

	// set things up so that it looks like we're running a CLI command (for now!)
	RootCmd = &cobra.Command{}

	legacyAmino := amino.NewLegacyAmino()
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	marshaler := amino.NewProtoCodec(interfaceRegistry)
	txConfig := authtx.NewTxConfig(marshaler, authtx.DefaultSignModes)
	//enccodec.RegisterLegacyAminoCodec(legacyAmino)
	//enccodec.RegisterInterfaces(interfaceRegistry)

	authtypes.RegisterInterfaces(interfaceRegistry)

	types.RegisterInterfaces(interfaceRegistry)
	nstypes.RegisterInterfaces(interfaceRegistry)

	ClientCtx = client.Context{}.
		WithCodec(marshaler).
		WithInterfaceRegistry(interfaceRegistry).
		WithTxConfig(txConfig).
		WithLegacyAmino(legacyAmino).
		WithInput(os.Stdin).
		WithAccountRetriever(authtypes.AccountRetriever{}).
		WithBroadcastMode(qadenaflags.BroadcastSync).
		WithHomeDir("NO-DEFAULT-HOME").
		WithKeyringOptions(qadenakr.Option()).
		WithViper(EnvPrefix)

	kb := keyring.NewInMemory(ClientCtx.Codec, qadenakr.Option())

	flags.AddTxFlagsToCmd(RootCmd)
	RootCmd.Flags().Set(flags.FlagChainID, *chainID)

	node := "tcp://" + *pioneerIP + ":26657"
	RootCmd.Flags().Set(flags.FlagNode, node)

	var err error

	ClientCtx, err = client.ReadPersistentCommandFlags(ClientCtx, RootCmd.Flags())
	if err != nil {
		c.LoggerError(logger, "couldn't read persistent command flags "+err.Error())
		return
	}

	ClientCtx.SkipConfirm = true

	c.LoggerDebug(logger, "clientCtx "+c.PrettyPrint(ClientCtx))
	ClientCtx = ClientCtx.WithKeyring(kb)

	storeKey := storetypes.NewKVStoreKey(types.StoreKey)
	//	memStoreKey := storetypes.NewMemoryStoreKey(types.MemStoreKey)

	//	db := tmdb.NewMemDB()

	db, err := tmdb.NewGoLevelDB("enclave", *homePath+"/enclave_data", nil)
	if err != nil {
		c.LoggerDebug(logger, "Error creating GoLevelDB")
		return
	}
	stateStore := store.NewCommitMultiStore(db, cosmossdkiolog.NewNopLogger(), storemetrics.NewNoOpMetrics())
	stateStore.MountStoreWithDB(storeKey, storetypes.StoreTypeIAVL, db)
	//	stateStore.MountStoreWithDB(memStoreKey, sdk.StoreTypeMemory, nil)

	serverCtx := sdk.NewContext(stateStore, tmproto.Header{}, false, cosmossdkiolog.NewNopLogger())

	registry := codectypes.NewInterfaceRegistry()
	cdc := amino.NewProtoCodec(registry)

	stateStore.LoadLatestVersion()

	cacheCtx, cacheCtxWrite := serverCtx.CacheContext()

	ekycServer := EKycServer{
		StoreKey:      storeKey,
		ServerCtx:     serverCtx,
		CacheCtx:      cacheCtx,
		CacheCtxWrite: cacheCtxWrite,
		Cdc:           cdc,
		HomePath:      *homePath,
		RealEnclave:   *realEnclave,
	}

	if !ekycServer.loadEnclaveParams() {
		c.LoggerInfo(logger, "Enclave params could not be loaded, but this is ok if the enclave has not yet been initialized.")
	}

	// set armor passphrase
	if *armorPrivK != "" && *armorPassPhrase != "" {
		ekycServer.initServer(*ekycName, *armorPrivK, *armorPassPhrase)
	}

	// new gin http server
	router := gin.Default()

	v1 := router.Group("/ekyc/1.0.0")

	{

		// this is for new EKYC
		v1.POST("/new-kyc", ekycServer.newKYC)
		v1.POST("/notify-user-new-kyc", ekycServer.notifyUserNewKYC)
		v1.POST("/authenticate-user-new-kyc", ekycServer.authenticateUserNewKYC)
		v1.POST("/liveness-url-new-kyc", ekycServer.livenessURLNewKYC)
		v1.POST("/validate-liveness-new-kyc", ekycServer.validateLivenessNewKYC)
		v1.POST("/submit-new-kyc", ekycServer.submitNewKYC)

		// this is for reuse EKYC
		v1.POST("/reuse-kyc", ekycServer.reuseKYC)
		v1.POST("/submit-kyc", ekycServer.submitKYC)
		v1.POST("/authenticate-user-reuse-kyc", ekycServer.authenticateUserReuseKYC)

		// bulk submit EKYC
		v1.POST("/bulk-submit-kyc", ekycServer.bulkSubmitKYC)

		// register kyc provider
		v1.POST("/register-kyc-provider", ekycServer.registerKYCProvider)

		// get kyc provider list
		v1.GET("/get-kyc-providers", func(context *gin.Context) {
			// make copy of Providers but only return the friendly name and the name
			providers := make([]Provider, len(ekycServer.privateEnclaveParams.Providers))
			for i, p := range ekycServer.privateEnclaveParams.Providers {
				providers[i].Name = p.Name
				providers[i].FriendlyName = p.FriendlyName
				providers[i].Logo = p.Logo
			}

			context.JSON(http.StatusOK, providers)
		})

		v1.POST("/notify-user-reuse-kyc", ekycServer.notifyUserReuseKYCRequest)
		v1.HEAD("/", func(context *gin.Context) {
			context.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	v2 := router.Group("/ekyc/2.0.0")

	{
		// for EKYC
		v2.POST("/begin-kyc", ekycServer.beginKYC)               // pass in phone number, sends SMS via Twilio, returns sessionID
		v2.POST("/authenticate-kyc", ekycServer.authenticateKYC) // pass in sessionID, some personal info (e.g. last name, possibly a PIN to protect the KYC record); returns error if not authenticated; returns whether a reusable KYC was found, and if so, some info about it and a session ID for the reuse KYC flow; if no reuseable KYC was found, still return a session ID for the new KYC flow

		v2.POST("/authenticate-otp", ekycServer.authenticateOTP) // pass in sessionID, OTP; returns error if not authenticated; return ok otherwise

		// after authenticate-kyc, for reuse KYC flow
		v2.POST("/confirm-reuse-kyc", ekycServer.confirmReuseKYC) // pass in sessionID from authenticateKYC to confirm that the user would like to reuse the KYC

		// after authenticate-kyc, for new KYC flow
		v2.POST("/confirm-new-kyc", ekycServer.confirmNewKYC) // pass in sessionID from authenticateKYC to start the collection of KYC data
		// after confirm-new-kyc, for new KYC flow
		v2.GET("/collect-new-kyc/:referenceID", ekycServer.collectNewKYC) // pass in referenceID from confirm-new-kyc, returns an HTML page with embedded iframe that collects the KYC data
		// check status of KYC
		v2.GET("/status-kyc/:referenceID", ekycServer.statusKYC) // pass in sessionID from authenticateKYC to check the status of the KYC
		// submit new KYC
		v2.POST("/submit-new-kyc", ekycServer.submitNewKYCv2) // pass in sessionID from statusKYC to confirm that the user would like to submit the KYC

		// webhook for new KYC flow from Advai
		v2.POST("/webhook-submit-kyc", ekycServer.webhookSubmitKYC) // pass in sessionID from authenticateKYC to confirm that the user would like to reuse the KYC

		// the following are used by KYC providers to submit KYC data
		// single submit EKYC
		v2.POST("/submit-kyc", ekycServer.submitKYC)
		// bulk submit EKYC
		v2.POST("/bulk-submit-kyc", ekycServer.bulkSubmitKYC)

		// the following is used by the EKYC server to add themselves as a KYC provider
		// register kyc provider
		v2.POST("/register-kyc-provider", ekycServer.registerKYCProvider)

		// get kyc provider list
		v2.GET("/get-kyc-providers", func(context *gin.Context) {
			// make copy of Providers but only return the friendly name and the name
			providers := make([]Provider, len(ekycServer.privateEnclaveParams.Providers))
			for i, p := range ekycServer.privateEnclaveParams.Providers {
				providers[i].Name = p.Name
				providers[i].FriendlyName = p.FriendlyName
				providers[i].Logo = p.Logo
			}

			context.JSON(http.StatusOK, providers)
		})

		// for testing if the endpoint is up
		v2.HEAD("/", func(context *gin.Context) {
			context.JSON(http.StatusOK, gin.H{"status": "ok"})
		})
	}

	router.Run(":" + strconv.Itoa(*port))
}
