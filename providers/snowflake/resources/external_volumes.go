// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"strings"
	"sync"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/snowflake/connection"
)

// mqlSnowflakeExternalVolumeInternal memoizes the per-volume DESCRIBE response.
// SHOW EXTERNAL VOLUMES reports only the name, write flag, and comment, so the
// storage locations come from a DESCRIBE call made at most once per volume.
type mqlSnowflakeExternalVolumeInternal struct {
	descOnce      sync.Once
	descLocations []any
	descErr       error
}

func (r *mqlSnowflakeAccount) externalVolumes() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
	volumes, err := conn.Client().ExternalVolumes.Show(context.Background(),
		sdk.NewShowExternalVolumeRequest())
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(volumes))
	for i := range volumes {
		mqlVolume, err := newMqlSnowflakeExternalVolume(r.MqlRuntime, volumes[i])
		if err != nil {
			return nil, err
		}
		list = append(list, mqlVolume)
	}
	return list, nil
}

func newMqlSnowflakeExternalVolume(runtime *plugin.Runtime, volume sdk.ExternalVolume) (*mqlSnowflakeExternalVolume, error) {
	r, err := CreateResource(runtime, "snowflake.externalVolume", map[string]*llx.RawData{
		"__id":        llx.StringData("snowflake.externalVolume/" + volume.Name),
		"name":        llx.StringData(volume.Name),
		"allowWrites": llx.BoolData(volume.AllowWrites),
		"comment":     llx.StringData(volume.Comment),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlSnowflakeExternalVolume), nil
}

func (r *mqlSnowflakeExternalVolume) storageLocations() ([]any, error) {
	r.descOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.SnowflakeConnection)
		props, err := conn.Client().ExternalVolumes.Describe(context.Background(),
			sdk.NewAccountObjectIdentifier(r.Name.Data))
		if err != nil {
			r.descErr = err
			return
		}
		r.descLocations = externalVolumeStorageLocations(props)
	})
	if r.descErr != nil {
		return nil, r.descErr
	}
	return r.descLocations, nil
}

// externalVolumeStorageLocations extracts the storage locations from a
// DESCRIBE EXTERNAL VOLUME response. The describe output is a flat property
// list in which each location is one row under the STORAGE_LOCATIONS parent,
// whose value is a JSON object holding that location's provider, base URL, and
// credentials.
//
// A value that does not parse as a JSON object is preserved rather than
// dropped: it is reported as a location carrying NAME and the unparsed
// STORAGE_LOCATION text, so an unexpected describe format shows up in the
// results instead of silently reading as "no storage locations".
func externalVolumeStorageLocations(props []sdk.ExternalVolumeProperty) []any {
	out := []any{}
	for _, prop := range props {
		if !strings.EqualFold(prop.Parent, "STORAGE_LOCATIONS") {
			continue
		}

		var location map[string]any
		if err := json.Unmarshal([]byte(prop.Value), &location); err == nil && location != nil {
			out = append(out, location)
			continue
		}
		out = append(out, map[string]any{
			"NAME":             prop.Name,
			"STORAGE_LOCATION": prop.Value,
		})
	}
	return out
}
