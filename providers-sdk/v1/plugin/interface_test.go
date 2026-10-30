// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type legacyDataProvider struct {
	ProviderPlugin
	read  bool
	write bool
}

func (p *legacyDataProvider) GetData(*DataReq) (*DataRes, error) {
	p.read = true
	return &DataRes{Error: "legacy read"}, nil
}

func (p *legacyDataProvider) StoreData(*StoreReq) (*StoreRes, error) {
	p.write = true
	return &StoreRes{}, nil
}

func TestDataContextLegacyCompatibility(t *testing.T) {
	p := &legacyDataProvider{}
	res, err := GetDataContext(context.Background(), p, &DataReq{})
	require.NoError(t, err)
	require.Equal(t, "legacy read", res.Error)
	require.True(t, p.read)
	_, err = StoreDataContext(context.Background(), p, &StoreReq{})
	require.NoError(t, err)
	require.True(t, p.write)
}

func TestDataContextDoesNotStartCancelledCalls(t *testing.T) {
	p := &legacyDataProvider{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := GetDataContext(ctx, p, &DataReq{})
	require.ErrorIs(t, err, context.Canceled)
	_, err = StoreDataContext(ctx, p, &StoreReq{})
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, p.read)
	require.False(t, p.write)
}
