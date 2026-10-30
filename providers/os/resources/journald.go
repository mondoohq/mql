// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann
// author: Tim Smith

package resources

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/spf13/afero"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/parsers"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/multierr"
)

type mqlJournaldConfigInternal struct {
	lock sync.Mutex

	settingsLock     sync.Mutex
	settingsResolved bool
	settings         *journaldSettings
	settingsErr      error
}

func initJournaldConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in journald.config initialization, it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")

		delete(args, "path")
	}

	return args, nil, nil
}

const defaultJournaldConfig = "/etc/systemd/journald.conf"

type journaldConfigSection struct {
	name       string
	params     map[string]string
	paramOrder []string
}

func (s *mqlJournaldConfig) id() (string, error) {
	file := s.GetFile()
	if file.Error != nil {
		return "", file.Error
	}

	return file.Data.Path.Data, nil
}

func (s *mqlJournaldConfig) file() (*mqlFile, error) {
	configPath := defaultJournaldConfig
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if ok {
		found, err := findSystemdMainConfig(conn.FileSystem(), "journald.conf")
		if err != nil {
			return nil, err
		}
		if found != "" {
			configPath = found
		}
	}

	return newFile(s.MqlRuntime, configPath)
}

// parses the journald config file and creates the resources
func (s *mqlJournaldConfig) parse(file *mqlFile) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if file == nil {
		return errors.New("no base journald config file to read")
	}

	files, err := s.configFiles(file)
	if err != nil {
		return err
	}

	filePath := file.GetPath()
	if filePath.Error != nil {
		return filePath.Error
	}

	sections := map[string]*journaldConfigSection{}
	sectionOrder := []string{}

	for _, configFile := range files {
		content, err := fileRequiredContent(configFile)
		if err != nil {
			return err
		}

		unit, err := parsers.ParseUnit(content)
		if err != nil {
			return fmt.Errorf("failed to parse journald config: %w", err)
		}

		mergeJournaldConfig(unit, sections, &sectionOrder)
	}

	var errs multierr.Errors
	sectionResources := []any{}

	for i, sectionName := range sectionOrder {
		sectionData := sections[sectionName]
		sectionID := fmt.Sprintf("%s/%s/%d", filePath.Data, sectionData.name, i)
		paramResources := []any{}

		for j, paramName := range sectionData.paramOrder {
			paramID := fmt.Sprintf("%s/%s/%d", sectionID, paramName, j)
			param, err := CreateResource(s.MqlRuntime, ResourceJournaldConfigSectionParam, map[string]*llx.RawData{
				"__id":  llx.StringData(paramID),
				"name":  llx.StringData(paramName),
				"value": llx.StringData(sectionData.params[paramName]),
			})
			if err != nil {
				errs.Add(fmt.Errorf("failed to create param resource for '%s' in section '%s': %w", paramName, sectionData.name, err))
				continue
			}
			paramResources = append(paramResources, param)
		}

		section, err := CreateResource(s.MqlRuntime, ResourceJournaldConfigSection, map[string]*llx.RawData{
			"__id":   llx.StringData(sectionID),
			"name":   llx.StringData(sectionData.name),
			"params": llx.ArrayData(paramResources, types.Resource(ResourceJournaldConfigSectionParam)),
		})
		if err != nil {
			errs.Add(fmt.Errorf("failed to create section resource for '%s': %w", sectionData.name, err))
			continue
		}

		sectionResources = append(sectionResources, section)
	}

	s.Sections.Data = sectionResources
	s.Sections.State = plugin.StateIsSet
	s.Sections.Error = errs.Deduplicate()
	return s.Sections.Error
}

func (s *mqlJournaldConfig) configFiles(file *mqlFile) ([]*mqlFile, error) {
	filePath := file.GetPath()
	if filePath.Error != nil {
		return nil, filePath.Error
	}

	files := []*mqlFile{file}
	conn, ok := s.MqlRuntime.Connection.(shared.Connection)
	if !ok {
		return files, nil
	}

	if isSystemdConfigMainPath(filePath.Data, "journald.conf") {
		dropins, err := findSystemdConfigDropins(conn.FileSystem(), "journald.conf")
		if err != nil {
			return nil, err
		}
		for _, dropin := range dropins {
			dropinFile, err := newFile(s.MqlRuntime, dropin)
			if err != nil {
				return nil, err
			}
			files = append(files, dropinFile)
		}
		return files, nil
	}

	matches, err := afero.Glob(conn.FileSystem(), filePath.Data+".d/*.conf")
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		dropinFile, err := newFile(s.MqlRuntime, match)
		if err != nil {
			return nil, err
		}
		files = append(files, dropinFile)
	}

	return files, nil
}

func mergeJournaldConfig(unit *parsers.Unit, sections map[string]*journaldConfigSection, sectionOrder *[]string) {
	for _, unitSection := range unit.Sections {
		sectionData, ok := sections[unitSection.Name]
		if !ok {
			sectionData = &journaldConfigSection{
				name:   unitSection.Name,
				params: map[string]string{},
			}
			sections[unitSection.Name] = sectionData
			*sectionOrder = append(*sectionOrder, unitSection.Name)
		}

		for _, unitParam := range unitSection.Params {
			val := unitParam.Value
			if slices.Contains(journaldDowncaseKeywords, unitParam.Name) {
				val = strings.ToLower(val)
			}

			if _, ok := sectionData.params[unitParam.Name]; !ok {
				sectionData.paramOrder = append(sectionData.paramOrder, unitParam.Name)
			}
			sectionData.params[unitParam.Name] = val
		}
	}
}

// returns the sections of the journald config, eg [Journal], [Upload], etc
func (s *mqlJournaldConfig) sections(file *mqlFile) ([]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}
	return s.Sections.Data, s.Sections.Error
}

// params is deprecated, use sections instead
func (s *mqlJournaldConfig) params(file *mqlFile) (map[string]any, error) {
	if err := s.parse(file); err != nil {
		return nil, err
	}

	// For backward compatibility, return the [Journal] section's params as a map
	for _, sectionAny := range s.Sections.Data {
		section := sectionAny.(*mqlJournaldConfigSection)
		name := section.GetName()
		if name.Error != nil {
			continue
		}

		if name.Data != "Journal" {
			continue
		}

		params := section.GetParams()
		if params.Error != nil {
			return nil, params.Error
		}

		result := make(map[string]any, len(params.Data))
		for _, paramAny := range params.Data {
			param := paramAny.(*mqlJournaldConfigSectionParam)
			paramName := param.GetName()
			paramValue := param.GetValue()
			if paramName.Error != nil || paramValue.Error != nil {
				continue
			}
			result[paramName.Data] = paramValue.Data
		}
		return result, nil
	}

	return map[string]any{}, nil
}

// These are the boolean options in journald.conf which are case insensitive
// See https://www.man7.org/linux/man-pages/man5/journald.conf.5.html
var journaldDowncaseKeywords = []string{
	"Compress",
	"Seal",
	"ForwardToSyslog",
	"ForwardToKMsg",
	"ForwardToConsole",
	"ForwardToWall",
	"ForwardToSocket",
	"ReadKMsg",
	"Audit",
}
