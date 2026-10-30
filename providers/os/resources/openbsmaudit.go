// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"errors"
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const defaultAuditControlPath = "/etc/security/audit_control"

func initOpenBSMAudit(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// OpenBSM audit is only supported on macOS and FreeBSD
	conn := runtime.Connection.(shared.Connection)
	platform := conn.Asset().Platform

	supported := platform.IsFamily("darwin") || platform.Name == "freebsd"
	if !supported {
		return nil, nil, errors.New("openBSMAudit resource is only supported on macOS and FreeBSD")
	}

	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in openBSMAudit initialization, it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
	} else {
		args["path"] = llx.StringData(defaultAuditControlPath)
	}

	return args, nil, nil
}

func (s *mqlOpenBSMAudit) id() (string, error) {
	return s.Path.Data, nil
}

func (s *mqlOpenBSMAudit) file() (*mqlFile, error) {
	path := s.Path.Data
	if path == "" {
		path = defaultAuditControlPath
	}

	f, err := CreateResource(s.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(path),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (s *mqlOpenBSMAudit) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlOpenBSMAudit) params(content string) (map[string]any, error) {
	res := make(map[string]any)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse key:value pairs
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		res[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return res, nil
}

func (s *mqlOpenBSMAudit) dir(params map[string]any) (string, error) {
	if val, ok := params["dir"]; ok {
		if strVal, ok := val.(string); ok {
			return strVal, nil
		}
	}
	return "", nil
}

func (s *mqlOpenBSMAudit) flags(params map[string]any) ([]any, error) {
	if val, ok := params["flags"]; ok {
		if strVal, ok := val.(string); ok {
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) minfree(params map[string]any) (int64, error) {
	if val, ok := params["minfree"]; ok {
		if strVal, ok := val.(string); ok {
			if num, err := strconv.ParseInt(strVal, 10, 64); err == nil {
				return num, nil
			}
		}
	}
	return 0, nil
}

func (s *mqlOpenBSMAudit) naflags(params map[string]any) ([]any, error) {
	if val, ok := params["naflags"]; ok {
		if strVal, ok := val.(string); ok {
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) policy(params map[string]any) ([]any, error) {
	if val, ok := params["policy"]; ok {
		if strVal, ok := val.(string); ok {
			policies := strings.Split(strVal, ",")
			result := make([]any, len(policies))
			for i, policy := range policies {
				result[i] = strings.TrimSpace(policy)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) filesz(params map[string]any) (string, error) {
	if val, ok := params["filesz"]; ok {
		if strVal, ok := val.(string); ok {
			return strVal, nil
		}
	}
	return "", nil
}

func (s *mqlOpenBSMAudit) expireAfter(params map[string]any) (string, error) {
	if val, ok := params["expire-after"]; ok {
		if strVal, ok := val.(string); ok {
			return strVal, nil
		}
	}
	return "", nil
}

func (s *mqlOpenBSMAudit) superuserSetSflagsMask(params map[string]any) ([]any, error) {
	if val, ok := params["superuser-set-sflags-mask"]; ok {
		if strVal, ok := val.(string); ok {
			if strVal == "" {
				return []any{}, nil
			}
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) superuserClearSflagsMask(params map[string]any) ([]any, error) {
	if val, ok := params["superuser-clear-sflags-mask"]; ok {
		if strVal, ok := val.(string); ok {
			if strVal == "" {
				return []any{}, nil
			}
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) memberSetSflagsMask(params map[string]any) ([]any, error) {
	if val, ok := params["member-set-sflags-mask"]; ok {
		if strVal, ok := val.(string); ok {
			if strVal == "" {
				return []any{}, nil
			}
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}

func (s *mqlOpenBSMAudit) memberClearSflagsMask(params map[string]any) ([]any, error) {
	if val, ok := params["member-clear-sflags-mask"]; ok {
		if strVal, ok := val.(string); ok {
			if strVal == "" {
				return []any{}, nil
			}
			flags := strings.Split(strVal, ",")
			result := make([]any, len(flags))
			for i, flag := range flags {
				result[i] = strings.TrimSpace(flag)
			}
			return result, nil
		}
	}
	return []any{}, nil
}
