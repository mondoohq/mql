// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/jomei/notionapi"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// richTextToString concatenates plain-text segments; a wrong result is silent
// (an empty or truncated title), so pin the empty, single, and multi-segment
// cases.
func TestRichTextToString(t *testing.T) {
	tests := []struct {
		name string
		in   []notionapi.RichText
		want string
	}{
		{name: "nil", in: nil, want: ""},
		{name: "empty", in: []notionapi.RichText{}, want: ""},
		{
			name: "single",
			in:   []notionapi.RichText{{PlainText: "hello"}},
			want: "hello",
		},
		{
			name: "multi-segment",
			in: []notionapi.RichText{
				{PlainText: "hello "},
				{PlainText: "world"},
				{PlainText: "!"},
			},
			want: "hello world!",
		},
		{
			name: "empty segment between",
			in: []notionapi.RichText{
				{PlainText: "a"},
				{PlainText: ""},
				{PlainText: "b"},
			},
			want: "ab",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := richTextToString(tc.in); got != tc.want {
				t.Fatalf("richTextToString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// pageTitle scans a property map by type and falls back to "". A bug here
// silently reports a page with no title, so cover the no-properties,
// wrong-type-only, single-title, and title-among-others cases.
func TestPageTitle(t *testing.T) {
	titleProp := &notionapi.TitleProperty{
		Type:  notionapi.PropertyTypeTitle,
		Title: []notionapi.RichText{{PlainText: "My "}, {PlainText: "Page"}},
	}
	richTextProp := &notionapi.RichTextProperty{
		Type:     notionapi.PropertyTypeRichText,
		RichText: []notionapi.RichText{{PlainText: "not the title"}},
	}

	tests := []struct {
		name  string
		props notionapi.Properties
		want  string
	}{
		{name: "nil properties", props: nil, want: ""},
		{name: "empty properties", props: notionapi.Properties{}, want: ""},
		{
			name:  "no title property",
			props: notionapi.Properties{"Notes": richTextProp},
			want:  "",
		},
		{
			name:  "single title property",
			props: notionapi.Properties{"Name": titleProp},
			want:  "My Page",
		},
		{
			name:  "title among other properties",
			props: notionapi.Properties{"Notes": richTextProp, "Name": titleProp},
			want:  "My Page",
		},
		{
			name: "empty title property",
			props: notionapi.Properties{"Name": &notionapi.TitleProperty{
				Type:  notionapi.PropertyTypeTitle,
				Title: []notionapi.RichText{},
			}},
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := pageTitle(tc.props); got != tc.want {
				t.Fatalf("pageTitle(%v) = %q, want %q", tc.props, got, tc.want)
			}
		})
	}
}

// isPubliclyShared is a derived predicate over the publicUrl field; empty means
// private, non-empty means published to the web.
func TestIsPubliclyShared(t *testing.T) {
	tests := []struct {
		name      string
		publicURL string
		want      bool
	}{
		{name: "empty is private", publicURL: "", want: false},
		{name: "non-empty is public", publicURL: "https://foo.notion.site/x", want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := &mqlNotionPage{
				PublicUrl: plugin.TValue[string]{Data: tc.publicURL, State: plugin.StateIsSet},
			}
			got, err := p.isPubliclyShared()
			if err != nil {
				t.Fatalf("isPubliclyShared() error = %v", err)
			}
			if got != tc.want {
				t.Fatalf("isPubliclyShared() = %v, want %v (publicURL=%q)", got, tc.want, tc.publicURL)
			}
		})
	}
}

// mqlNotionPageFromAPI feeds a raw notionapi.Properties map through
// convert.JsonToDict. This pins the round-trip: it must not error, must not
// panic on nested interface property values, and must preserve the property
// keys as a queryable dict.
func TestPropertiesJsonToDictRoundTrip(t *testing.T) {
	props := notionapi.Properties{
		"Name": &notionapi.TitleProperty{
			Type:  notionapi.PropertyTypeTitle,
			Title: []notionapi.RichText{{PlainText: "Example"}},
		},
		"Notes": &notionapi.RichTextProperty{
			Type:     notionapi.PropertyTypeRichText,
			RichText: []notionapi.RichText{{PlainText: "a note"}},
		},
		"Count": &notionapi.NumberProperty{
			Type:   notionapi.PropertyTypeNumber,
			Number: 42,
		},
	}

	dict, err := convert.JsonToDict(props)
	if err != nil {
		t.Fatalf("JsonToDict returned error: %v", err)
	}
	for _, key := range []string{"Name", "Notes", "Count"} {
		if _, ok := dict[key]; !ok {
			t.Fatalf("JsonToDict dropped property %q; got keys %v", key, keysOf(dict))
		}
	}

	// Keys surviving is not the same as values surviving: a property type
	// whose marshaler dropped its payload would still leave the key behind,
	// and the field would read as an empty object rather than as an error.
	// So reach into each one for the value that actually matters.
	if got := nestedPlainText(t, dict, "Name", "title"); got != "Example" {
		t.Errorf("title property plain_text = %q, want %q", got, "Example")
	}
	if got := nestedPlainText(t, dict, "Notes", "rich_text"); got != "a note" {
		t.Errorf("rich_text property plain_text = %q, want %q", got, "a note")
	}

	count, ok := dict["Count"].(map[string]any)
	if !ok {
		t.Fatalf("Count property = %T, want map[string]any", dict["Count"])
	}
	// JSON has one number type, so an int arrives as a float64.
	if n, ok := count["number"].(float64); !ok || n != 42 {
		t.Errorf("number property = %v (%T), want 42", count["number"], count["number"])
	}

	// An empty property map must round-trip to an empty (non-nil) dict, not
	// an error.
	empty, err := convert.JsonToDict(notionapi.Properties{})
	if err != nil {
		t.Fatalf("JsonToDict(empty) returned error: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("JsonToDict(empty) = %v, want empty map", empty)
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// nestedPlainText pulls prop[arrayKey][0]["plain_text"] out of a
// round-tripped rich-text-shaped property, failing the test if the shape is
// not what Notion documents.
func nestedPlainText(t *testing.T, dict map[string]any, prop, arrayKey string) string {
	t.Helper()

	obj, ok := dict[prop].(map[string]any)
	if !ok {
		t.Fatalf("property %q = %T, want map[string]any", prop, dict[prop])
	}
	arr, ok := obj[arrayKey].([]any)
	if !ok {
		t.Fatalf("property %q key %q = %T, want []any", prop, arrayKey, obj[arrayKey])
	}
	if len(arr) == 0 {
		t.Fatalf("property %q key %q round-tripped to an empty array", prop, arrayKey)
	}
	first, ok := arr[0].(map[string]any)
	if !ok {
		t.Fatalf("property %q key %q [0] = %T, want map[string]any", prop, arrayKey, arr[0])
	}
	text, ok := first["plain_text"].(string)
	if !ok {
		t.Fatalf("property %q key %q [0].plain_text = %T, want string", prop, arrayKey, first["plain_text"])
	}
	return text
}
