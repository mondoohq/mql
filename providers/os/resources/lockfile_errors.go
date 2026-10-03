// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/resources/languages"
)

// parseLockfile reads the lockfile or manifest at path and parses it with
// extractor. A file that cannot be read is an error, a refusal classified as
// forbidden, and a file that does not parse is malformed data.
func parseLockfile(afs *afero.Afero, path string, extractor languages.Extractor) (languages.Bom, error) {
	data, err := afs.ReadFile(path)
	if err != nil {
		return nil, lockfileReadError(path, err)
	}
	bom, err := extractor.Parse(bytes.NewReader(data), path)
	if err != nil {
		return nil, llx.MalformedData(fmt.Errorf("cannot parse %s: %w", path, err))
	}
	return bom, nil
}

// lockfileReadError is the error for a lockfile, or a directory holding one,
// at path that could not be read. A refusal is classified as forbidden; a
// path that does not exist keeps os.ErrNotExist, which the callers read as
// absence.
func lockfileReadError(path string, err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return err
	}
	err = fmt.Errorf("cannot read %s: %w", path, err)
	if errors.Is(err, os.ErrPermission) {
		return llx.Forbidden(err)
	}
	return err
}

// lockfileExists reports whether a lockfile is at path. A path that does not
// exist is no lockfile; any other failure to stat it, such as a directory the
// scan may not enter, is an error, so it is not mistaken for absence.
func lockfileExists(afs *afero.Afero, path string) (bool, error) {
	_, err := afs.Stat(path)
	if err == nil {
		return true, nil
	}
	// a parent that is a file is no lockfile either
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) {
		return false, nil
	}
	return false, lockfileReadError(path, err)
}

// lockfileIsDir reports whether path is a directory. A path that does not
// exist is returned as an os.ErrNotExist error.
func lockfileIsDir(afs *afero.Afero, path string) (bool, error) {
	isDir, err := afs.IsDir(path)
	if err != nil {
		return false, lockfileReadError(path, err)
	}
	return isDir, nil
}

// explicitLockfileError is what a packages resource reports for err, the
// error from collecting the path its query named. A path that does not exist
// has no packages. Anything else that kept a lockfile from being read or
// parsed is an error: reporting no packages for it lets a check that no
// vulnerable package is installed pass on a file it never read.
//
// Before structured errors (ADR 046 §9) a lockfile the scan was refused was
// reported as having no packages; that stays without the flag. A file that
// does not parse was never a legitimate empty list and is an error either way.
func explicitLockfileError(err error) error {
	for _, e := range flattenErrors(err) {
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if !plugin.StructuredErrors() && errors.Is(e, llx.ErrForbidden) {
			continue
		}
		return e
	}
	return nil
}

// skipLockfileError logs err, the error from collecting one of the default
// search paths, and drops it. Discovery searches many places a project may
// be, and one unreadable or broken project must not fail the search, but it
// must not disappear without a trace either.
func skipLockfileError(path string, err error) {
	for _, e := range flattenErrors(err) {
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		log.Warn().Err(e).Str("path", path).Msg("could not read packages, skipping")
	}
}

// classifyReadErrors marks each refusal among the errors joined in err as
// forbidden, for scanners outside this package that return the filesystem's
// errors as they are.
func classifyReadErrors(err error) error {
	errs := flattenErrors(err)
	for i, e := range errs {
		if errors.Is(e, os.ErrPermission) && !errors.Is(e, llx.ErrForbidden) {
			errs[i] = llx.Forbidden(e)
		}
	}
	return errors.Join(errs...)
}

// isFsError reports whether err came from reading the filesystem rather than
// from making sense of what was read.
func isFsError(err error) bool {
	var pathErr *fs.PathError
	return errors.As(err, &pathErr) || errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist)
}

// flattenErrors returns the errors errors.Join combined into err, in order.
func flattenErrors(err error) []error {
	if err == nil {
		return nil
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		var res []error
		for _, e := range joined.Unwrap() {
			res = append(res, flattenErrors(e)...)
		}
		return res
	}
	return []error{err}
}
