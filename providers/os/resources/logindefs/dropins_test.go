// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package logindefs

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The cases below are the ones probed with useradd on SLES 16 and openSUSE
// Leap 16; the comment on each states the PASS_MAX_DAYS useradd applied.
func TestDropInPaths(t *testing.T) {
	t.Run("vendor drop-ins come before /etc drop-ins whatever their names", func(t *testing.T) {
		// /etc 10=10 + vendor 90=90 gave 10, /etc 90=90 + vendor 10=10 gave 90
		assert.Equal(t,
			[]string{"/usr/etc/login.defs.d/90-vendor.defs", "/etc/login.defs.d/10-admin.defs"},
			DropInPaths([]string{"90-vendor.defs"}, []string{"10-admin.defs"}))
	})

	t.Run("each directory is sorted by name", func(t *testing.T) {
		// /etc 10-x=90 + /etc 90-x=10 gave 10
		assert.Equal(t,
			[]string{"/etc/login.defs.d/10-x.defs", "/etc/login.defs.d/90-x.defs"},
			DropInPaths(nil, []string{"90-x.defs", "10-x.defs"}))
	})

	t.Run("/etc shadows a vendor file of the same name", func(t *testing.T) {
		// /etc 50=77 + vendor 50=55 gave 77
		assert.Equal(t,
			[]string{"/usr/etc/login.defs.d/40-other.defs", "/etc/login.defs.d/50-a.defs"},
			DropInPaths([]string{"50-a.defs", "40-other.defs"}, []string{"50-a.defs"}))
	})

	t.Run("only .defs files count", func(t *testing.T) {
		// /etc x.conf=44 left the main file's 99999 in place
		assert.Empty(t, DropInPaths([]string{"README"}, []string{"x.conf", "y.defs.rpmsave", ".defs"}))
	})
}

func TestOverlayDropIns(t *testing.T) {
	main := Parse(strings.NewReader("PASS_MAX_DAYS\t90\nUID_MIN\t\t1000\n"))
	dropIn := Parse(strings.NewReader("PASS_MAX_DAYS 99999 # relaxed\n"))
	later := Parse(strings.NewReader("UID_MIN 5000\n"))

	got := Overlay(main, dropIn, later)
	assert.Equal(t, "99999", got["PASS_MAX_DAYS"], "a drop-in replaces the main file's value")
	assert.Equal(t, "5000", got["UID_MIN"])
	assert.Equal(t, "90", main["PASS_MAX_DAYS"], "the layers are not modified")
}
