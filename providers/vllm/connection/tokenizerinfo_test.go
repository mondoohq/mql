// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

// tokenizerInfoJSON is shaped after /tokenizer_info, which returns the
// contents of tokenizer_config.json plus the loaded tokenizer class and the
// chat template in force.
const tokenizerInfoJSON = `{
  "tokenizer_class": "PreTrainedTokenizerFast",
  "model_max_length": 131072,
  "add_bos_token": true,
  "add_eos_token": false,
  "clean_up_tokenization_spaces": false,
  "bos_token": "<|begin_of_text|>",
  "eos_token": {"content": "<|eot_id|>", "lstrip": false, "normalized": false},
  "pad_token": null,
  "chat_template": "{% for message in messages %}{{ message.role }}{% endfor %}"
}`

func TestParseTokenizerInfo(t *testing.T) {
	info, err := ParseTokenizerInfo([]byte(tokenizerInfoJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := derefString(info.TokenizerClass); got != "PreTrainedTokenizerFast" {
		t.Fatalf("tokenizerClass got %q", got)
	}
	if got := derefInt(info.ModelMaxLength); got != 131072 {
		t.Fatalf("modelMaxLength got %d", got)
	}
	if info.AddBosToken == nil || !*info.AddBosToken {
		t.Fatalf("addBosToken got %v want true", info.AddBosToken)
	}
	if info.AddEosToken == nil || *info.AddEosToken {
		t.Fatalf("addEosToken got %v want false", info.AddEosToken)
	}
	if info.CleanUpTokenizationSpec == nil || *info.CleanUpTokenizationSpec {
		t.Fatalf("cleanUpTokenizationSpaces got %v want false", info.CleanUpTokenizationSpec)
	}
	// A bare-string special token and a serialized AddedToken must both read
	// as the literal token.
	if got := derefString(info.BosToken); got != "<|begin_of_text|>" {
		t.Fatalf("bosToken got %q", got)
	}
	if got := derefString(info.EosToken); got != "<|eot_id|>" {
		t.Fatalf("eosToken got %q", got)
	}
	if info.PadToken != nil {
		t.Fatalf("padToken got %q want null", *info.PadToken)
	}
	if info.ChatTemplate == nil {
		t.Fatal("chatTemplate must be read")
	}
	sum := sha256.Sum256([]byte(*info.ChatTemplate))
	if got := derefString(info.ChatTemplateSHA256); got != hex.EncodeToString(sum[:]) {
		t.Fatalf("chatTemplateSha256 got %q", got)
	}
}

// A tokenizer with no template configured must leave the template and its
// digest null rather than reporting the digest of an empty string.
func TestParseTokenizerInfoWithoutChatTemplate(t *testing.T) {
	info, err := ParseTokenizerInfo([]byte(`{"tokenizer_class":"GPT2Tokenizer"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ChatTemplate != nil {
		t.Fatalf("chatTemplate got %q want null", *info.ChatTemplate)
	}
	if info.ChatTemplateSHA256 != nil {
		t.Fatalf("chatTemplateSha256 got %q want null", *info.ChatTemplateSHA256)
	}
	if info.ModelMaxLength != nil {
		t.Fatalf("modelMaxLength got %d want null", *info.ModelMaxLength)
	}
}

// Hugging Face writes an "effectively unlimited" length as a float far beyond
// int64. Reporting the wrapped conversion would be a fabricated number.
func TestParseTokenizerInfoSentinelLength(t *testing.T) {
	info, err := ParseTokenizerInfo([]byte(`{"model_max_length": 1000000000000000019884624838656}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.ModelMaxLength != nil {
		t.Fatalf("modelMaxLength got %d want null", *info.ModelMaxLength)
	}
}

func TestSpecialToken(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
		null  bool
	}{
		{name: "bare string", value: "</s>", want: "</s>"},
		{name: "added token object", value: map[string]any{"content": "</s>"}, want: "</s>"},
		{name: "object without content", value: map[string]any{"lstrip": true}, null: true},
		{name: "null", value: nil, null: true},
		{name: "unexpected type", value: float64(3), null: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := specialToken(tt.value)
			if tt.null {
				if got != nil {
					t.Fatalf("got %q want null", *got)
				}
				return
			}
			if got == nil || *got != tt.want {
				t.Fatalf("got %v want %q", got, tt.want)
			}
		})
	}
}

// /tokenizer_info is registered only when the endpoint is explicitly enabled,
// so its absence must not surface as an error.
func TestTokenizerInfoAbsentRouteIsNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
	info, err := conn.TokenizerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info != nil {
		t.Fatalf("got %+v want nil", info)
	}
}

func TestTokenizerInfoFetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tokenizer_info" {
			t.Fatalf("path got %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(tokenizerInfoJSON))
	}))
	defer server.Close()

	conn := &VllmConnection{client: server.Client(), baseURL: server.URL}
	info, err := conn.TokenizerInfo(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info == nil || derefString(info.TokenizerClass) != "PreTrainedTokenizerFast" {
		t.Fatalf("got %+v", info)
	}
}
