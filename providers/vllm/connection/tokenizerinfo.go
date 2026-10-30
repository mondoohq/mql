// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	tokenizerInfoPath = "/tokenizer_info"
	maxTokenizerBody  = 8 << 20
)

// TokenizerInfo is the tokenizer configuration a vLLM server reports on
// /tokenizer_info: the contents of tokenizer_config.json, plus the class name
// of the loaded tokenizer and the chat template in force. The template is the
// prompt-assembly logic, so a template that differs from the one shipped with
// the model is the place role confusion and injection get introduced.
type TokenizerInfo struct {
	TokenizerClass          *string
	ChatTemplate            *string
	ChatTemplateSHA256      *string
	ModelMaxLength          *int64
	AddBosToken             *bool
	AddEosToken             *bool
	BosToken                *string
	EosToken                *string
	PadToken                *string
	UnkToken                *string
	CleanUpTokenizationSpec *bool
}

type tokenizerInfoDoc struct {
	TokenizerClass          *string `json:"tokenizer_class"`
	ChatTemplate            *string `json:"chat_template"`
	ModelMaxLength          any     `json:"model_max_length"`
	AddBosToken             *bool   `json:"add_bos_token"`
	AddEosToken             *bool   `json:"add_eos_token"`
	BosToken                any     `json:"bos_token"`
	EosToken                any     `json:"eos_token"`
	PadToken                any     `json:"pad_token"`
	UnkToken                any     `json:"unk_token"`
	CleanUpTokenizationSpec *bool   `json:"clean_up_tokenization_spaces"`
}

// TokenizerInfo fetches and decodes /tokenizer_info once per connection. The
// route is registered only when the server was started with
// --enable-tokenizer-info-endpoint, so a default server answers 404 and this
// returns a nil TokenizerInfo with no error.
func (c *VllmConnection) TokenizerInfo(ctx context.Context) (*TokenizerInfo, error) {
	c.tokenizerInfoOnce.Do(func() {
		resp, err := c.Request(ctx, http.MethodGet, tokenizerInfoPath, true, "")
		if err != nil {
			c.tokenizerInfoErr = err
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented {
			discardProbeBody(resp.Body)
			return
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			discardProbeBody(resp.Body)
			c.tokenizerInfoErr = fmt.Errorf("vllm: /tokenizer_info returned HTTP %d", resp.StatusCode)
			return
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenizerBody))
		if err != nil {
			c.tokenizerInfoErr = err
			return
		}
		info, err := ParseTokenizerInfo(raw)
		if err != nil {
			c.tokenizerInfoErr = err
			return
		}
		c.tokenizerInfo = info
	})
	return c.tokenizerInfo, c.tokenizerInfoErr
}

// ParseTokenizerInfo decodes a /tokenizer_info payload.
func ParseTokenizerInfo(raw []byte) (*TokenizerInfo, error) {
	var doc tokenizerInfoDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("vllm: failed to parse /tokenizer_info response: %w", err)
	}

	info := &TokenizerInfo{
		TokenizerClass:          doc.TokenizerClass,
		ChatTemplate:            doc.ChatTemplate,
		ModelMaxLength:          jsonInt64Ptr(doc.ModelMaxLength),
		AddBosToken:             doc.AddBosToken,
		AddEosToken:             doc.AddEosToken,
		BosToken:                specialToken(doc.BosToken),
		EosToken:                specialToken(doc.EosToken),
		PadToken:                specialToken(doc.PadToken),
		UnkToken:                specialToken(doc.UnkToken),
		CleanUpTokenizationSpec: doc.CleanUpTokenizationSpec,
	}
	if doc.ChatTemplate != nil {
		sum := sha256.Sum256([]byte(*doc.ChatTemplate))
		digest := hex.EncodeToString(sum[:])
		info.ChatTemplateSHA256 = &digest
	}
	return info, nil
}

// specialToken reads a tokenizer_config.json special token, which is written
// either as a bare string or as the serialized form of a Hugging Face
// AddedToken, an object whose "content" key holds the literal token.
func specialToken(value any) *string {
	switch v := value.(type) {
	case string:
		return &v
	case map[string]any:
		content, ok := v["content"].(string)
		if !ok {
			return nil
		}
		return &content
	default:
		return nil
	}
}
