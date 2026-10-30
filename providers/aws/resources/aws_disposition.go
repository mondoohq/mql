// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
)

// disposition is what a lister should do about an AWS error.
//
// The same error text can mean three very different things, and conflating them
// is how a scan reports a clean result it never actually collected. Deciding
// this once, centrally, keeps every lister out of the business of guessing.
type disposition int

const (
	// dispositionFail means the answer is unknown because the call went wrong:
	// a throttle, a 5xx, a malformed request. The caller must surface it.
	dispositionFail disposition = iota
	// dispositionEmpty means there is genuinely nothing to report: the service
	// is not deployed in this region, or the account never opted in. Zero rows
	// is the truthful answer.
	dispositionEmpty
	// dispositionUnreadable means the read was refused. Zero rows is NOT the
	// truthful answer, so the caller records a coverage gap rather than letting
	// the absence pass for an all-clear.
	dispositionUnreadable
)

// accessDeniedCodes are the API error codes AWS returns when the caller is not
// permitted to make the call.
//
// These are matched on smithy's ErrorCode rather than on the rendered message.
// Codes are part of the API contract; messages are prose AWS rewrites at will,
// and a guard keyed on prose stops firing the day a wording changes.
var accessDeniedCodes = map[string]bool{
	"AccessDenied":                true,
	"AccessDeniedException":       true,
	"AuthorizationError":          true,
	"AuthFailure":                 true,
	"UnauthorizedOperation":       true,
	"UnauthorizedException":       true,
	"MissingAuthenticationToken":  true,
	"InvalidClientTokenId":        true,
	"UnrecognizedClientException": true,
	"InvalidAccessKeyId":          true,
	"SignatureDoesNotMatch":       true,
}

// serviceAbsentCodes are the API error codes meaning the service or operation
// does not exist here, as opposed to existing and being refused.
var serviceAbsentCodes = map[string]bool{
	// The region exists but the account has not opted into it.
	"OptInRequired": true,
	// The endpoint resolved but does not implement this operation, which is how
	// several services answer in regions they have not been deployed to yet.
	"UnknownOperationException": true,
	"InvalidAction":             true,
	"NotImplemented":            true,
	"MethodNotAllowed":          true,
	// The service exists but has never been turned on for this account.
	"SubscriptionRequiredException": true,
}

// dispositionRule matches errors whose meaning cannot be read off the code
// alone. Every field left at its zero value is a wildcard.
type dispositionRule struct {
	// code, when set, must equal the smithy API error code.
	code string
	// messageAny, when set, requires the error text to contain at least one of
	// these substrings, compared after apostrophe normalization.
	messageAny []string
	// disposition is the answer when the rule matches.
	disposition disposition
}

func (r dispositionRule) matches(err error, msg string) bool {
	if r.code != "" {
		var ae smithy.APIError
		if !errors.As(err, &ae) || ae.ErrorCode() != r.code {
			return false
		}
	}
	if len(r.messageAny) == 0 {
		return true
	}
	for _, want := range r.messageAny {
		if strings.Contains(msg, want) {
			return true
		}
	}
	return false
}

// serviceRules carries per-service overrides, consulted before the generic code
// tables.
//
// A handful of services have no distinct code for "this was never enabled for
// your account" and reuse AccessDeniedException or ResourceNotFoundException,
// putting the distinguishing fact in the message. Those are the only cases that
// legitimately need message matching, and confining them here keeps the rest of
// the provider off prose entirely.
//
// A key may be narrowed to a group of endpoints as "<service>/<scope>", for
// when one service's endpoints disagree about what an error code means.
// Classification tries the narrow key first and then falls back to the bare
// service, so a scope only has to state where it differs.
var serviceRules = map[string][]dispositionRule{
	"macie2": {
		{
			code:        "AccessDeniedException",
			messageAny:  []string{"Macie is not enabled", "Macie isn't enabled"},
			disposition: dispositionEmpty,
		},
		{
			code:        "ResourceNotFoundException",
			messageAny:  []string{"Macie is not enabled", "Macie isn't enabled", "not enabled for your account"},
			disposition: dispositionEmpty,
		},
	},
	// The single-record configuration reads (GetMacieSession,
	// GetAdministratorAccount, GetAutomatedDiscoveryConfiguration) answer
	// not-found when the feature has never been configured in the region, so
	// for these a bare not-found is an empty result. The list endpoints get no
	// such licence: a not-found there is a resource that vanished mid-read,
	// which the caller must see.
	"macie2/config": {
		{
			code:        "ResourceNotFoundException",
			disposition: dispositionEmpty,
		},
		// The automated-discovery read has a shape of its own that never names
		// Macie: AccessDeniedException "Account Id: [...] has not been
		// onboarded". Onboarding state is not a permission gap, and no IAM
		// denial is phrased this way, so matching it does not reintroduce the
		// swallowing this table exists to prevent.
		{
			code:        "AccessDeniedException",
			messageAny:  []string{"has not been onboarded"},
			disposition: dispositionEmpty,
		},
	},
	"securitylake": {
		{
			code:        "ResourceNotFoundException",
			messageAny:  []string{"Security Lake is not enabled", "Security Lake isn't enabled"},
			disposition: dispositionEmpty,
		},
	},
	"guardduty": {
		{
			code:        "BadRequestException",
			messageAny:  []string{"is not enabled", "isn't enabled"},
			disposition: dispositionEmpty,
		},
	},
}

// transportRegionMisses are the failures that happen below the API layer, where
// there is no code to match because no request ever completed: the endpoint does
// not resolve, or every attempt failed to leave the client.
//
// This is the one place raw text matching is unavoidable. The strings are the
// SDK's and Go's own, not AWS service prose, so they are far more stable than
// the service messages this table exists to avoid.
var transportRegionMisses = []string{
	"no such host",
	"UnknownEndpoint",
	"could not resolve endpoint",
}

// classificationKeys expands a classification scope into the keys to consult,
// narrowest first: "macie2/config" yields "macie2/config" then "macie2".
func classificationKeys(service string) []string {
	if base, _, found := strings.Cut(service, "/"); found {
		return []string{service, base}
	}
	return []string{service}
}

// serviceName strips any endpoint scope, giving the name to report a coverage
// gap under. Users think in services, not in the groupings we classify by.
func serviceName(service string) string {
	base, _, _ := strings.Cut(service, "/")
	return base
}

// classifyError decides what a lister should do about err from the named
// service. service is the AWS service id, matching the key used to build the
// client (for example "ecr", "macie2", "rds"), optionally narrowed to a group
// of endpoints as "<service>/<scope>" - see serviceRules.
//
// Callers must not pass a nil error: there is nothing to classify, and the
// question only arises on an error path. A nil is answered with
// dispositionFail because that is the one answer that cannot silently drop a
// region's real results.
func classifyError(service string, err error) disposition {
	if err == nil {
		return dispositionFail
	}
	msg := awsNormalizeApostrophes(err.Error())

	// The narrow key wins where it speaks; the bare service covers the rest.
	for _, key := range classificationKeys(service) {
		for _, rule := range serviceRules[key] {
			if rule.matches(err, msg) {
				return rule.disposition
			}
		}
	}

	for _, miss := range transportRegionMisses {
		if strings.Contains(msg, miss) {
			return dispositionEmpty
		}
	}
	// An endpoint that resolves but fails every single attempt to send is a
	// service that is not really deployed in this region. Both halves are
	// required: a throttle or a 5xx also exhausts retries, and the caller must
	// see those.
	if strings.Contains(msg, "exceeded maximum number of attempts") &&
		strings.Contains(msg, "request send failed") {
		return dispositionEmpty
	}

	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch {
		case accessDeniedCodes[ae.ErrorCode()]:
			return dispositionUnreadable
		case serviceAbsentCodes[ae.ErrorCode()]:
			return dispositionEmpty
		}
	}

	return dispositionFail
}
