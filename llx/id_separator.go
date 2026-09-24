// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

// IDSeparator joins the parts of a composite resource __id, e.g. a file path
// and the entry it contains. It is the ASCII Unit Separator: it cannot appear
// in identifiers, paths, or URLs, so a joined id can never be read two ways.
//
// Resource ids are stored, and NUL (\x00) is rejected by common storage
// backends (e.g. PostgreSQL text and jsonb columns), so it must not be used.
//
// This is deliberately distinct from the recording layer's key separator
// (the ASCII Record Separator, \x1e), which joins a resource name to its id:
// records separate resource+id pairs, units separate the fields within an id.
const IDSeparator = "\x1f"
