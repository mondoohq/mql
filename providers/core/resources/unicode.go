// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/core/resources/classifier"
)

func unicodeInputHash(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	bs := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(bs)
}

func (r *mqlUnicode) id() (string, error) {
	return "unicode/" + unicodeInputHash(r.Input.Data), nil
}

func (r *mqlUnicode) classification() ([]any, error) {
	input := r.Input.Data

	c := classifier.NewUnicodeClassifier()
	characterInfo, err := c.ClassifyString(input)
	if err != nil {
		return nil, err
	}

	id := unicodeInputHash(r.Input.Data)

	res := []any{}
	for i := range characterInfo {
		ci, err := newMqlCharacterInfo(r.MqlRuntime, id, characterInfo[i])
		if err != nil {
			return nil, err
		}
		res = append(res, ci)
	}

	return res, nil
}

func newMqlCharacterInfo(runtime *plugin.Runtime, id string, info classifier.CharacterInfo) (*mqlUnicodeCharInfo, error) {
	mqlResource, err := CreateResource(runtime, ResourceUnicodeCharInfo,
		map[string]*llx.RawData{
			"__id":          llx.StringData(id + "/" + strconv.Itoa(info.Position)),
			"position":      llx.IntData(info.Position),
			"char":          llx.StringData(info.Character),
			"codePoint":     llx.StringData(info.UnicodePoint),
			"majorCategory": llx.StringData(info.MajorCategory),
			"category":      llx.StringData(info.Category),
			"description":   llx.StringData(info.Description),
		})
	if err != nil {
		return nil, err
	}
	return mqlResource.(*mqlUnicodeCharInfo), nil
}

func (r *mqlUnicode) categories() ([]any, error) {
	input := r.Input.Data

	c := classifier.NewUnicodeClassifier()
	summary, err := c.GetCategorySummary(input)
	if err != nil {
		return nil, err
	}

	id := unicodeInputHash(r.Input.Data)

	res := []any{}
	for k, v := range summary {
		mqlResource, err := CreateResource(r.MqlRuntime, ResourceUnicodeCategory,
			map[string]*llx.RawData{
				"__id":          llx.StringData(id + "/" + k),
				"category":      llx.StringData(k),
				"majorCategory": llx.StringData(string(k[0])),
				"description":   llx.StringData(classifier.CategoryDescriptions[k]),
				"count":         llx.IntData(v),
			})
		if err != nil {
			return nil, err
		}

		res = append(res, mqlResource)
	}

	return res, nil
}
