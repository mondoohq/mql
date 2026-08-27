// copyright: 2019, Dominik Richter and Christoph Hartmann
// author: Dominik Richter
// author: Christoph Hartmann

package resources

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/v13/checksums"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/os/resources/parsers"
	"go.mondoo.com/mql/v13/providers/os/resources/plist"
	"go.mondoo.com/mql/v13/utils/xml"
	"sigs.k8s.io/yaml"
)

func fileFromPathOrContent(runtime *plugin.Runtime, args map[string]*llx.RawData) error {
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return errors.New("wrong type for 'path' it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return err
		}
		args["file"] = llx.ResourceData(f, "file")
		delete(args, "path")
	} else {
		if x, ok := args["content"]; ok {
			content := x.Value.(string)
			virtualPath := "in-memory://" + checksums.New.Add(content).String()
			f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
				"path":    llx.StringData(virtualPath),
				"content": llx.StringData(content),
				"exists":  llx.BoolTrue,
			})
			if err != nil {
				return err
			}
			args["file"] = llx.ResourceData(f, "file")
		}
	}
	return nil
}

func initParseIni(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if err := fileFromPathOrContent(runtime, args); err != nil {
		return nil, nil, err
	}

	if _, ok := args["delimiter"]; !ok {
		args["delimiter"] = llx.StringData("=")
	}

	return args, nil, nil
}

func (s *mqlParseIni) id() (string, error) {
	if s.File.Data == nil {
		return "", errors.New("no file provided for parse.ini")
	}

	file := s.File.Data
	del := s.Delimiter.Data
	return file.Path.Data + del, nil
}

func (s *mqlParseIni) content(file *mqlFile) (string, error) {
	return fileContentOrEmpty(file)
}

func (s *mqlParseIni) sections(content string, delimiter string) (map[string]any, error) {
	ini := parsers.ParseIni(content, delimiter)

	res := make(map[string]any, len(ini.Fields))
	for k, v := range ini.Fields {
		res[k] = v
	}

	return res, nil
}

func (s *mqlParseIni) params(sections map[string]any) (map[string]any, error) {
	res := sections[""]
	if res == nil {
		return map[string]any{}, nil
	}
	return res.(map[string]any), nil
}

func initParseJson(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if err := fileFromPathOrContent(runtime, args); err != nil {
		return nil, nil, err
	}

	return args, nil, nil
}

func (s *mqlParseJson) id() (string, error) {
	if s.File.Data == nil {
		return "", errors.New("no file provided for parse.json")
	}

	file := s.File.Data
	return file.Path.Data, nil
}

func (s *mqlParseJson) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlParseJson) params(content string) (any, error) {
	if content == "" {
		return nil, nil
	}

	return parseJSONContent(content)
}

func parseJSONContent(content string) (any, error) {
	var res any
	if err := json.Unmarshal([]byte(content), &res); err != nil {
		sanitized, changed := sanitizeJSONStructuralNoise(content)
		if !changed {
			return nil, err
		}

		if sanitizeErr := json.Unmarshal([]byte(sanitized), &res); sanitizeErr != nil {
			return nil, fmt.Errorf("failed to parse JSON: %w; sanitized parse failed: %v", err, sanitizeErr)
		}
		return res, nil
	}
	return res, nil
}

func sanitizeJSONStructuralNoise(content string) (string, bool) {
	var (
		out        = make([]byte, 0, len(content))
		stack      []byte
		changed    bool
		lastSig    byte
		lastSigPos = -1
	)

	inString := false
	escaped := false

	setLastSig := func(ch byte) {
		lastSig = ch
		lastSigPos = len(out) - 1
	}

	trimTrailingComma := func() {
		end := len(out)
		for end > 0 {
			switch out[end-1] {
			case ' ', '\t', '\n', '\r':
				end--
			case ',':
				commaPos := lastSigPos
				if commaPos < 0 || commaPos >= len(out) {
					commaPos = end - 1
				}
				out = out[:commaPos]
				lastSig = 0
				lastSigPos = -1
				for i := commaPos - 1; i >= 0; i-- {
					switch out[i] {
					case ' ', '\t', '\n', '\r':
						continue
					default:
						lastSig = out[i]
						lastSigPos = i
						return
					}
				}
				return
			default:
				return
			}
		}
	}

	for i := 0; i < len(content); i++ {
		ch := content[i]
		if inString {
			out = append(out, ch)
			if escaped {
				escaped = false
				continue
			}
			switch ch {
			case '\\':
				escaped = true
			case '"':
				inString = false
				setLastSig(ch)
			}
			continue
		}

		switch ch {
		case '"':
			inString = true
			out = append(out, ch)
		case ' ', '\t', '\n', '\r':
			out = append(out, ch)
		case '{', '[':
			stack = append(stack, ch)
			out = append(out, ch)
			setLastSig(ch)
		case ',':
			next := nextSignificantJSONByte(content, i+1)
			if lastSig == '{' || lastSig == '[' || lastSig == ',' || lastSig == ':' || next == '}' || next == ']' {
				changed = true
				continue
			}
			out = append(out, ch)
			setLastSig(ch)
		case '}':
			if len(stack) == 0 {
				changed = true
				continue
			}
			if stack[len(stack)-1] == '[' {
				changed = true
				continue
			}
			if lastSig == ',' {
				trimTrailingComma()
				changed = true
			}
			stack = stack[:len(stack)-1]
			out = append(out, ch)
			setLastSig(ch)
		case ']':
			if len(stack) == 0 {
				changed = true
				continue
			}
			if stack[len(stack)-1] == '{' {
				changed = true
				continue
			}
			if lastSig == ',' {
				trimTrailingComma()
				changed = true
			}
			stack = stack[:len(stack)-1]
			out = append(out, ch)
			setLastSig(ch)
		default:
			out = append(out, ch)
			setLastSig(ch)
		}
	}

	return string(out), changed
}

func nextSignificantJSONByte(content string, start int) byte {
	for i := start; i < len(content); i++ {
		switch content[i] {
		case ' ', '\t', '\n', '\r':
			continue
		default:
			return content[i]
		}
	}
	return 0
}

func initParseXml(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if err := fileFromPathOrContent(runtime, args); err != nil {
		return nil, nil, err
	}

	return args, nil, nil
}

func (s *mqlParseXml) id() (string, error) {
	if s.File.Data == nil {
		return "", errors.New("no file provided for parse.xml")
	}

	file := s.File.Data
	return file.Path.Data, nil
}

func (s *mqlParseXml) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlParseXml) params(content string) (any, error) {
	return xml.Parse([]byte(content))
}

func initParseYaml(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if err := fileFromPathOrContent(runtime, args); err != nil {
		return nil, nil, err
	}

	return args, nil, nil
}

func (s *mqlParseYaml) id() (string, error) {
	if s.File.Data == nil {
		return "", errors.New("no file provided for parse.yaml")
	}

	file := s.File.Data
	return file.Path.Data, nil
}

func (s *mqlParseYaml) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlParseYaml) params(content string) (map[string]any, error) {
	res := make(map[string](any))

	if content == "" {
		return nil, nil
	}

	err := yaml.Unmarshal([]byte(content), &res)
	if err != nil {
		return nil, err
	}

	return res, nil
}

func (s *mqlParseYaml) documents(content string) ([]any, error) {
	if content == "" {
		return []any{}, nil
	}

	var documents []any

	// Split content by YAML document separator
	yamlDocs := strings.Split(content, "---")

	for _, doc := range yamlDocs {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var parsed any
		err := yaml.Unmarshal([]byte(doc), &parsed)
		if err != nil {
			return nil, fmt.Errorf("failed to parse YAML document: %w", err)
		}

		if parsed != nil {
			documents = append(documents, parsed)
		}
	}

	return documents, nil
}

func initParsePlist(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if err := fileFromPathOrContent(runtime, args); err != nil {
		return nil, nil, err
	}
	return args, nil, nil
}

func (s *mqlParsePlist) id() (string, error) {
	if s.File.Data == nil {
		return "", errors.New("no file provided for parse.plist")
	}

	file := s.File.Data
	return file.Path.Data, nil
}

func (s *mqlParsePlist) content(file *mqlFile) (string, error) {
	c := file.GetContent()
	return c.Data, c.Error
}

func (s *mqlParsePlist) params(content string) (map[string]any, error) {
	return plist.Decode(strings.NewReader(content))
}

func initParseCertificates(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// resolve path to file
	if x, ok := args["path"]; ok {
		path, ok := x.Value.(string)
		if !ok {
			return nil, nil, errors.New("wrong type for 'path' in certificates initialization, it must be a string")
		}

		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": llx.StringData(path),
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")

	} else if x, ok := args["content"]; ok {
		content := x.Value.(string)
		virtualPath := "in-memory://" + checksums.New.Add(content).String()
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path":    llx.StringData(virtualPath),
			"content": llx.StringData(content),
			"exists":  llx.BoolTrue,
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")
		args["path"] = llx.StringData(virtualPath)
	} else {
		return nil, nil, errors.New("missing 'path' or 'content' for parse.certificates initialization")
	}

	return args, nil, nil
}

func certificatesid(path string) string {
	return "certificates:" + path
}

func (a *mqlParseCertificates) id() (string, error) {
	f := a.File.Data
	if f == nil {
		return "", errors.New("missing file in parse certificate")
	}

	return certificatesid(f.Path.Data), nil
}

func (a *mqlParseCertificates) file() (*mqlFile, error) {
	f, err := CreateResource(a.MqlRuntime, "file", map[string]*llx.RawData{
		"path": llx.StringData(a.Path.Data),
	})
	if err != nil {
		return nil, err
	}
	return f.(*mqlFile), nil
}

func (a *mqlParseCertificates) content(file *mqlFile) (string, error) {
	res := file.GetContent()
	return res.Data, res.Error
}

func (p *mqlParseCertificates) list(content string, path string) ([]any, error) {
	certificates, err := p.MqlRuntime.CreateSharedResource("certificates", map[string]*llx.RawData{
		"pem": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}

	list, err := p.MqlRuntime.GetSharedData("certificates", certificates.MqlID(), "list")
	if err != nil {
		return nil, err
	}

	return list.Value.([]any), nil
}

func initParseOpenpgp(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// resolve path to file
	if x, ok := args["path"]; ok {
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path": x,
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")

	} else if x, ok := args["content"]; ok {
		content := x.Value.(string)
		virtualPath := "in-memory://" + checksums.New.Add(content).String()
		f, err := CreateResource(runtime, "file", map[string]*llx.RawData{
			"path":    llx.StringData(virtualPath),
			"content": llx.StringData(content),
			"exists":  llx.BoolTrue,
		})
		if err != nil {
			return nil, nil, err
		}
		args["file"] = llx.ResourceData(f, "file")

	} else {
		return nil, nil, errors.New("missing 'path' or 'content' for parse.openpgp initialization")
	}

	return args, nil, nil
}

func (a *mqlParseOpenpgp) id() (string, error) {
	if a.File.Error != nil {
		return "", a.File.Error
	}
	if a.File.Data == nil {
		return "", errors.New("no file provided for parse.openpgp")
	}

	return a.File.Data.Path.Data, nil
}

func (a *mqlParseOpenpgp) content(file plugin.Resource) (string, error) {
	res := file.(*mqlFile).GetContent()
	return res.Data, res.Error
}

func (p *mqlParseOpenpgp) list(content string) ([]any, error) {
	certificates, err := p.MqlRuntime.CreateSharedResource("openpgp.entities", map[string]*llx.RawData{
		"content": llx.StringData(content),
	})
	if err != nil {
		return nil, err
	}

	list, err := p.MqlRuntime.GetSharedData("openpgp.entities", certificates.MqlID(), "list")
	if err != nil {
		return nil, err
	}

	return list.Value.([]any), nil
}
