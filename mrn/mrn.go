// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mrn

import (
	"errors"
	"net/url"
	"path"
	"regexp"
	"strings"
)

func ServiceID(serviceName string, baseDomain string) string {
	res := strings.TrimSuffix(serviceName, baseDomain)
	return res
}

func IsValid(mrn string) bool {
	x, err := url.Parse(mrn)
	if err != nil {
		return false
	}

	return x.Scheme == "" && x.Fragment == "" && x.RawQuery == ""
}

func NewMRN(fullResourceName string) (*MRN, error) {
	u, err := url.Parse(fullResourceName)
	if err != nil {
		return nil, err
	}

	path := strings.TrimLeft(u.EscapedPath(), "/")

	return &MRN{
		ServiceName:          u.Host,
		RelativeResourceName: path,
	}, nil
}

func NewChildMRN(ownerMRN string, resource string, resourceID string) (*MRN, error) {
	if !isValidResourceID(resourceID) {
		return nil, errors.New("invalid " + resource + " ID: " + resourceID)
	}

	mrn, err := NewMRN(ownerMRN)
	if err != nil {
		return nil, err
	}

	mrn.RelativeResourceName = path.Join(mrn.RelativeResourceName, resource, resourceID)
	return mrn, nil
}

func GetResource(mrn string, resource string) (string, error) {
	parsed, err := NewMRN(mrn)
	if err != nil {
		return "", err
	}

	res, err := parsed.ResourceID(resource)
	if err != nil {
		return "", errors.New("invalid " + resource + " in mrn: " + mrn)
	}
	return res, nil
}

// SafeComponentString sanitizes a string so that it can be safely used as a uri component for mrns
func SafeComponentString(s string) string {
	if s == "" {
		return s
	}
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "/", "-")
	return s
}

// ID: lowercase letters, digits, dots or hyphens, fewer than 200 chars, more than 4 chars.
// They may include dots/hyphens etc, e.g. 1.1.2-tmp-configured
var reResourceID = regexp.MustCompile(`^([\d-_\.]|[a-zA-Z]){4,200}$`)

func isValidResourceID(id string) bool {
	return reResourceID.MatchString(id)
}

// MRN follows Google's Design for resource names
// see https://google.aip.dev/122
type MRN struct {
	ServiceName          string
	RelativeResourceName string
}

func (mrn *MRN) String() string {
	return "//" + mrn.ServiceName + "/" + mrn.RelativeResourceName
}

func (mrn *MRN) Basename() string {
	keyValues := strings.Split(mrn.RelativeResourceName, "/")
	if len(keyValues) == 0 {
		return ""
	}
	return keyValues[len(keyValues)-1]
}

func (mrn *MRN) ResourceID(collectionId string) (string, error) {
	keyValues := strings.Split(mrn.RelativeResourceName, "/")
	for i := 0; i < len(keyValues); {
		if keyValues[i] == collectionId {
			if i+1 < len(keyValues) {
				return keyValues[i+1], nil
			} else {
				return "", errors.New("invalid mrn collection id scheme: " + mrn.String())
			}
		}
		i = i + 2
	}
	return "", errors.New("could not find collection id: " + collectionId)
}

func (mrn *MRN) Equals(resource string) bool {
	parsed, err := NewMRN(resource)
	if err != nil {
		return false
	}
	if parsed.ServiceName == mrn.ServiceName && parsed.RelativeResourceName == mrn.RelativeResourceName {
		return true
	}
	return false
}
