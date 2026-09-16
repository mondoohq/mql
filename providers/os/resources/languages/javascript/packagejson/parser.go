// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packagejson

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// packageJson allows parsing the package json file
type packageJson struct {
	Name            string                `json:"name"`
	Description     string                `json:"description"`
	Version         string                `json:"version"`
	Private         booleanField          `json:"private"`
	Homepage        string                `json:"homepage"`
	License         *packageJsonLicense   `json:"license"`
	Licenses        []packageJsonLicense  `json:"licenses"`
	Author          *packageJsonPeople    `json:"author"`
	Contributors    []packageJsonPeople   `json:"contributors"`
	Dependencies    map[string]string     `json:"dependencies"`
	DevDependencies map[string]string     `json:"devDependencies"`
	Repository      packageJsonRepository `json:"repository"`
	Engines         enginesField          `json:"engines"`
	CPU             []string              `json:"cpu"`
	OS              []string              `json:"os"`

	// evidence is a list of file paths where the package.json was found
	evidence []string `json:"-"`
}

type enginesField map[string]string

func (p *enginesField) UnmarshalJSON(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	// Default to an empty map
	n := map[string]string{}

	switch v := raw.(type) {
	case map[string]any:
		for key, value := range v {
			if strVal, ok := value.(string); ok {
				n[key] = strVal
			} else {
				log.Warn().Msgf("invalid type for engines[%s]", key)
			}
		}
	}

	*p = n

	return nil
}

type booleanField bool

func (p *booleanField) UnmarshalJSON(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	switch v := raw.(type) {
	case bool:
		*p = booleanField(v)
	case string:
		*p = strings.ToLower(v) == "true"
	default:
		return fmt.Errorf("invalid private field type: %T", v)
	}
	return nil
}

// packageJsonPeople represents the author of the package
// https://docs.npmjs.com/cli/v10/configuring-npm/package-json#people-fields-author-contributors
type packageJsonPeople struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	URL   string `json:"url"`
}

// authorPattern parses the single-string author string:
//
//	^: Asserts the start of the string.
//	([^<]+): Captures one or more characters that are not <. This is for the author's name.
//	\s+: Matches one or more whitespace characters.
//	<([^>]+)>: Captures the email address within angle brackets.
//	\s+: Matches one or more whitespace characters again.
//	\(([^)]+)\): Captures the URL within parentheses.
//	$: Asserts the end of the string.
var authorPattern = regexp.MustCompile(`^([^<]+)\s+<([^>]+)>(?:\s+\(([^)]+)\))?$`)

// UnmarshalJSON implements the json.Unmarshaler interface
// package.json author can be a string or a structured object
func (a *packageJsonPeople) UnmarshalJSON(b []byte) error {
	var authorStr string
	type authorStruct packageJsonPeople
	author := authorStruct{}

	// try to unmarshal as structured object
	err := json.Unmarshal(b, &author)
	if err == nil {
		a.Name = author.Name
		a.Email = author.Email
		a.URL = author.URL
		return nil
	}

	// try to unmarshal as string
	err = json.Unmarshal(b, &authorStr)
	if err == nil {
		matches := authorPattern.FindStringSubmatch(authorStr)
		if len(matches) == 4 {
			a.Name = matches[1]
			a.Email = matches[2]
			a.URL = matches[3]
			return nil
		}
		// if the pattern does not match, we assume the string is the name
		a.Name = authorStr
		return nil
	}

	return errors.New("could not unmarshal author: " + string(b))
}

func (a *packageJsonPeople) String() string {
	b := strings.Builder{}
	b.WriteString(a.Name)
	if a.Email != "" {
		fmt.Fprintf(&b, " <%s>", a.Email)
	}
	if a.URL != "" {
		fmt.Fprintf(&b, " (%s)", a.URL)
	}
	return b.String()
}

type packageJsonRepository struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Directory string `json:"directory"`
}

func (r *packageJsonRepository) UnmarshalJSON(b []byte) error {
	var repositoryStr string
	type repositoryStruct packageJsonRepository
	repo := repositoryStruct{}

	// try to unmarshal as structured object
	err := json.Unmarshal(b, &repo)
	if err == nil {
		r.Type = repo.Type
		r.URL = repo.URL
		r.Directory = repo.Directory
		return nil
	}

	// try to unmarshal as string
	err = json.Unmarshal(b, &repositoryStr)
	if err == nil {
		// handle case where the type is provided as prefix like `bitbucket:`
		parts := strings.SplitN(repositoryStr, ":", 2)
		if len(parts) == 2 {
			r.Type = parts[0]
			r.URL = parts[1]
			return nil
		} else {
			r.Type = "github"
			r.URL = repositoryStr
			return nil
		}
	}

	return errors.New("could not unmarshal repository: " + string(b))
}

type packageJsonLicense struct {
	Value string `json:"value"`
}

// UnmarshalJSON implements the json.Unmarshaler interface.
//
// A license is stated as a plain SPDX string today:
//
//	"license": "MIT"
//
// Before npm settled on that it was an object naming the license and linking
// its text, and the same object is what the members of the deprecated
// `licenses` array are:
//
//	"license":  { "type": "ISC", "url": "https://opensource.org/licenses/ISC" }
//	"licenses": [ { "type": "MIT", "url": "..." }, { "type": "Apache-2.0", ... } ]
//
// Both forms are read, and the object's `type` is the license. Its `url` is
// dropped: a link to the terms is not the identity of the terms, and a URL in a
// field consumers read as an identifier is worse than an empty one.
func (a *packageJsonLicense) UnmarshalJSON(b []byte) error {
	// try to unmarshal as string
	var licenseStr string
	if err := json.Unmarshal(b, &licenseStr); err == nil {
		a.Value = licenseStr
		return nil
	}

	// try to unmarshal as the deprecated object form
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(b, &obj); err == nil {
		a.Value = obj.Type
		return nil
	}

	// Any other shape states no license this can read. Leaving the value empty
	// keeps the rest of the package.json parsing rather than failing the file
	// over one malformed field.
	return nil
}
