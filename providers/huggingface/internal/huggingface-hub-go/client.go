// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package huggingface

import (
	"context"
	"net/http"
	"time"

	"go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/api"
	"go.mondoo.com/mql/providers/huggingface/internal/huggingface-hub-go/models"
)

const (
	DefaultBaseURL = "https://huggingface.co"
)

type Client struct {
	api *api.API
}

type ClientOption func(*Client)

func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.api.SetBaseURL(url)
	}
}

func WithToken(token string) ClientOption {
	return func(c *Client) {
		c.api.SetToken(token)
	}
}

func WithHTTPClient(client *http.Client) ClientOption {
	return func(c *Client) {
		c.api.SetHTTPClient(client)
	}
}

func NewClient(opts ...ClientOption) *Client {
	httpClient := &http.Client{
		Timeout: time.Second * 30,
	}

	client := &Client{
		api: api.NewAPI(DefaultBaseURL, httpClient, ""),
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

func (c *Client) GetModel(ctx context.Context, modelID string) (*models.Model, error) {
	return c.api.GetModel(ctx, modelID)
}

func (c *Client) GetDataset(ctx context.Context, datasetID string) (*models.Dataset, error) {
	return c.api.GetDataset(ctx, datasetID)
}

func (c *Client) GetSpace(ctx context.Context, spaceID string) (*models.Space, error) {
	return c.api.GetSpace(ctx, spaceID)
}

func (c *Client) GetRepoScan(ctx context.Context, repoType models.RepoType, repoID string) (*models.RepoScan, error) {
	return c.api.GetRepoScan(ctx, repoType, repoID)
}

func (c *Client) ListModels(ctx context.Context, opts *models.ModelListOptions) (*models.ModelList, error) {
	return c.api.ListModels(ctx, opts)
}

func (c *Client) ListDatasets(ctx context.Context, opts *models.DatasetListOptions) (*models.DatasetList, error) {
	return c.api.ListDatasets(ctx, opts)
}

func (c *Client) ListSpaces(ctx context.Context, opts *models.SpaceListOptions) (*models.SpaceList, error) {
	return c.api.ListSpaces(ctx, opts)
}

func (c *Client) ListInferenceEndpoints(ctx context.Context, namespace string) (*models.InferenceEndpointList, error) {
	return c.api.ListInferenceEndpoints(ctx, namespace)
}

func (c *Client) ListWebhooks(ctx context.Context, opts *models.WebhookListOptions) ([]models.Webhook, error) {
	return c.api.ListWebhooks(ctx, opts)
}

func (c *Client) WhoAmI(ctx context.Context) (*models.User, error) {
	return c.api.WhoAmI(ctx)
}

func (c *Client) GetModelDetail(ctx context.Context, modelID string) (*models.ModelDetail, error) {
	return c.api.GetModelDetail(ctx, modelID)
}

func (c *Client) DownloadModelFile(ctx context.Context, modelID, filePath string) ([]byte, error) {
	return c.api.DownloadModelFile(ctx, modelID, filePath)
}

func (c *Client) GetModelCard(ctx context.Context, modelID string, revision string) (*models.ModelCard, error) {
	return c.api.GetModelCard(ctx, modelID, revision)
}

func (c *Client) GetDatasetCard(ctx context.Context, datasetID string, revision string) (*models.DatasetCard, error) {
	return c.api.GetDatasetCard(ctx, datasetID, revision)
}
