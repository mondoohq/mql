// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manager

import (
	"strings"

	"github.com/cockroachdb/errors"
	mapstructure "github.com/go-viper/mapstructure/v2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/types"
)

type CredentialQueryResponse struct {
	// maps to credentials
	Type     string `json:"type,omitempty"`
	User     string `json:"user,omitempty"`      // user associated with the secret
	SecretId string `json:"secret_id,omitempty"` // id to use to fetch the secret from the source vault
}

func NewCredentialQueryRunner(credentialQuery string, runtime llx.Runtime) (*CredentialQueryRunner, error) {
	mqlExecutor := exec.New(runtime, mql.DefaultFeatures)

	// just empty props to ensure we can compile
	props := mqlc.SimpleProps{
		"mrn":      llx.StringPrimitive(""),
		"name":     llx.StringPrimitive(""),
		"labels":   llx.MapData(map[string]any{}, types.String).Result().Data,
		"platform": llx.MapData(map[string]any{}, types.String).Result().Data,
	}

	// test query to see if it compiles well
	_, err := exec.Exec(credentialQuery, runtime, nil, props)
	if err != nil {
		return nil, errors.Wrap(err, "could not compile the secret metadata function")
	}
	return &CredentialQueryRunner{
		mqlExecutor:         mqlExecutor,
		secretMetadataQuery: credentialQuery,
	}, nil
}

type CredentialQueryRunner struct {
	mqlExecutor         *exec.Executor
	secretMetadataQuery string
}

func (sq *CredentialQueryRunner) Run(a *inventory.Asset) (*vault.Credential, error) {
	// map labels to props
	labelProps := map[string]any{}
	labels := a.GetLabels()
	for k, v := range labels {
		labelProps[k] = v
	}

	// map platform to props
	var platformProps map[string]any
	if a.Platform != nil {
		platformProps = map[string]any{
			"name":    a.Platform.Name,
			"release": a.Platform.Version,
			"arch":    a.Platform.Arch,
		}
	} else {
		platformProps = map[string]any{}
	}

	props := mqlc.SimpleProps{
		"mrn":      llx.StringPrimitive(a.Mrn),
		"name":     llx.StringPrimitive(a.Name),
		"labels":   llx.MapData(labelProps, types.String).Result().Data,
		"platform": llx.MapData(platformProps, types.String).Result().Data,
	}

	value, err := sq.mqlExecutor.Exec(sq.secretMetadataQuery, props)
	if err != nil {
		return nil, err
	}

	sMeta := &CredentialQueryResponse{}
	decoder, _ := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata: nil,
		Result:   sMeta,
		TagName:  "json",
	})
	err = decoder.Decode(value.Value)

	code, ok := vault.CredentialType_value[strings.TrimSpace(sMeta.Type)]
	if !ok {
		log.Warn().Str("credential_type", sMeta.Type).Msg("unknown credential type used in credential query")
	}

	creds := &vault.Credential{
		Type:     vault.CredentialType(code),
		User:     sMeta.User,
		SecretId: sMeta.SecretId,
	}

	return creds, err
}
