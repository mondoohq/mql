// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sort"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestBigqueryLocations(t *testing.T) {
	if len(bigqueryLocations) == 0 {
		t.Fatal("bigqueryLocations is empty, every BigQuery listing would report nothing")
	}

	// A duplicate would list one location twice and report its reservations
	// twice, since each pass creates the same resources again.
	seen := map[string]struct{}{}
	for _, l := range bigqueryLocations {
		if _, ok := seen[l]; ok {
			t.Fatalf("location %q appears twice", l)
		}
		seen[l] = struct{}{}
	}

	// The multi-regions are where most reservations are actually bought, and
	// they are the two entries an alphabetical sort of the list would be most
	// likely to lose.
	for _, want := range []string{"US", "EU", "us-central1", "europe-west1", "aws-us-east-1"} {
		if _, ok := seen[want]; !ok {
			t.Fatalf("location %q missing from bigqueryLocations", want)
		}
	}
}

func TestBigqueryLocationUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "not found", err: status.Error(codes.NotFound, "no such parent"), want: true},
		{name: "unimplemented", err: status.Error(codes.Unimplemented, "not offered here"), want: true},
		{name: "invalid argument", err: status.Error(codes.InvalidArgument, "failed to parse the URI"), want: true},
		{name: "failed precondition", err: status.Error(codes.FailedPrecondition, "location unavailable"), want: true},

		// The one that decides whether the fix works. isSkippable folds a
		// permission denial in with "nothing here"; if this classifier did the
		// same, a project the caller cannot read would report an empty list from
		// every location and every assertion over it would pass vacuously.
		{name: "permission denied is not a location problem", err: status.Error(codes.PermissionDenied, "caller lacks bigquery.reservations.list"), want: false},
		{name: "unavailable is not a location problem", err: status.Error(codes.Unavailable, "backend unavailable"), want: false},
		{name: "plain error", err: fmt.Errorf("connection reset"), want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := bigqueryLocationUnsupported(tc.err); got != tc.want {
				t.Fatalf("bigqueryLocationUnsupported(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}

	// A classification has to survive a caller wrapping the error for context,
	// or the skip path stops firing the moment somebody adds a %w.
	t.Run("survives wrapping", func(t *testing.T) {
		wrapped := fmt.Errorf("listing reservations: %w", status.Error(codes.InvalidArgument, "bad parent"))
		if !bigqueryLocationUnsupported(wrapped) {
			t.Fatal("wrapped InvalidArgument was not recognized")
		}
	})
}

func TestListBigqueryLocations(t *testing.T) {
	t.Run("visits every location exactly once", func(t *testing.T) {
		var mu sync.Mutex
		visited := []string{}
		_, err := listBigqueryLocations(func(location string) ([]any, error) {
			mu.Lock()
			defer mu.Unlock()
			visited = append(visited, location)
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(visited) != len(bigqueryLocations) {
			t.Fatalf("visited %d locations, want %d", len(visited), len(bigqueryLocations))
		}
		sort.Strings(visited)
		want := append([]string{}, bigqueryLocations...)
		sort.Strings(want)
		for i := range want {
			if visited[i] != want[i] {
				t.Fatalf("visited[%d] = %q, want %q", i, visited[i], want[i])
			}
		}
	})

	t.Run("concatenates the results of every location", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			if location == "US" || location == "europe-west1" {
				return []any{location}, nil
			}
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("got %v, want two entries", got)
		}
	})

	// The bug this whole change exists to fix: a project with nothing
	// configured is a real, reportable answer, and it has to stay one.
	t.Run("no results anywhere is an empty list, not an error", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})

	t.Run("an unsupported location is skipped", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			if location == "US" {
				return []any{"reservation"}, nil
			}
			return nil, status.Error(codes.InvalidArgument, "not a BigQuery location for this project")
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %v, want the one readable location's result", got)
		}
	})

	t.Run("an API that is not enabled reports empty rather than failing", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			return nil, status.Error(codes.PermissionDenied,
				"BigQuery Reservation API has not been used in project 1234 before or it is disabled")
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v, want empty", got)
		}
	})

	// Denied everywhere must not look like "there is nothing here". This is the
	// distinction the issue asked for: the empty case has to be
	// distinguishable from the not-checked case.
	t.Run("denied in every location is an error, not an empty list", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			return nil, status.Error(codes.PermissionDenied, "caller lacks bigquery.reservations.list")
		})
		if err == nil {
			t.Fatalf("got %v and no error, want an error", got)
		}
		if got != nil {
			t.Fatalf("got %v alongside the error, want nil", got)
		}
	})

	// One unreachable location must not throw away what the others returned.
	t.Run("a partial failure returns what was read", func(t *testing.T) {
		got, err := listBigqueryLocations(func(location string) ([]any, error) {
			if location == "US" {
				return nil, status.Error(codes.PermissionDenied, "denied in this location only")
			}
			if location == "EU" {
				return []any{"reservation"}, nil
			}
			return nil, nil
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("got %v, want the readable location's result", got)
		}
	})
}
