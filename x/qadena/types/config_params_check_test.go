package types_test

import (
	"os"
	"testing"

	"github.com/c3qtech/qadena_v3/x/qadena/types"
	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"sigs.k8s.io/yaml"
)

// TestConfigYamlParamsUnmarshal reads the qadena params block out of config/config.yml and runs
// it through the same JSON decoding path genesis uses.  A type mismatch there (an int64 written
// as a bare number, a typo'd field name) would otherwise only show up when a chain is initialized.
func TestConfigYamlParamsUnmarshal(t *testing.T) {
	raw, err := os.ReadFile("../../../config/config.yml")
	if err != nil {
		t.Skipf("config/config.yml not readable: %v", err)
	}

	var cfg struct {
		Genesis struct {
			AppState struct {
				Qadena struct {
					Params map[string]interface{} `json:"params"`
				} `json:"qadena"`
			} `json:"app_state"`
		} `json:"genesis"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("config/config.yml is not valid yaml: %v", err)
	}

	params := cfg.Genesis.AppState.Qadena.Params
	if len(params) == 0 {
		t.Fatal("no qadena params found in config/config.yml")
	}

	paramsJSON, err := yaml.Marshal(params)
	if err != nil {
		t.Fatalf("couldn't re-marshal params: %v", err)
	}
	paramsJSON, err = yaml.YAMLToJSON(paramsJSON)
	if err != nil {
		t.Fatalf("couldn't convert params to json: %v", err)
	}

	cdc := codec.NewProtoCodec(codectypes.NewInterfaceRegistry())

	var p types.Params
	if err := cdc.UnmarshalJSON(paramsJSON, &p); err != nil {
		t.Fatalf("config params do not decode into types.Params: %v\n%s", err, paramsJSON)
	}

	// spot-check the update params so a silently-dropped field fails here
	if p.UpdateCredentialFee == "" {
		t.Error("update_credential_fee did not decode")
	}
	if p.UpdateNameMaxEditDistance == 0 || p.UpdateNameMaxEditDistancePercent == 0 || p.UpdateBirthdateMaxYearDelta == 0 {
		t.Errorf("update name/birthdate params did not decode: %+v", p)
	}
	if p.UpdateCredentialMinBlocksBetweenUpdates == 0 {
		t.Error("update_credential_min_blocks_between_updates did not decode")
	}
	if !p.UpdateCredentialAllowLastNameLifeEvent || !p.UpdateCredentialAllowGenderChange {
		t.Errorf("update gates did not decode: %+v", p)
	}
}
