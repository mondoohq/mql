// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package tomcat

import "strconv"

// WebXML is a servlet deployment descriptor: the global conf/web.xml or an
// application's WEB-INF/web.xml.
//
// The nested parts are exposed as dicts rather than resources. They are read
// far less often than server.xml, their element names map cleanly onto keys,
// and a dict keeps the descriptor usable for the parts nothing reads yet.
// Keys use the camelCase spelling of the element name, so <transport-guarantee>
// reads as transportGuarantee.
type WebXML struct {
	MetadataComplete    bool
	ErrorPages          []map[string]any
	SecurityConstraints []map[string]any
	LoginConfig         map[string]any
	SessionTimeout      int64
	CookieHTTPOnly      bool
	CookieSecure        bool
	Servlets            []map[string]any
	Filters             []map[string]any
}

// ParseWebXML parses a deployment descriptor. It returns nil when the document
// is empty or its root element is not <web-app>.
func ParseWebXML(data []byte) (*WebXML, error) {
	root, err := ParseXML(data)
	if err != nil {
		return nil, err
	}
	if root == nil || root.Name != "web-app" {
		return nil, nil
	}

	res := &WebXML{
		MetadataComplete:    root.AttrBool(false, "metadata-complete"),
		ErrorPages:          parseErrorPages(root),
		SecurityConstraints: parseSecurityConstraints(root),
		LoginConfig:         parseLoginConfig(root),
		Servlets:            parseServlets(root),
		Filters:             parseFilters(root),
	}

	if sessionConfig := root.Element("session-config"); sessionConfig != nil {
		if v, err := strconv.ParseInt(sessionConfig.ChildText("session-timeout"), 10, 64); err == nil {
			res.SessionTimeout = v
		}
		if cookieConfig := sessionConfig.Element("cookie-config"); cookieConfig != nil {
			res.CookieHTTPOnly = cookieConfig.ChildText("http-only") == "true"
			res.CookieSecure = cookieConfig.ChildText("secure") == "true"
		}
	}

	return res, nil
}

func parseErrorPages(root *Node) []map[string]any {
	res := []map[string]any{}
	for _, page := range root.Elements("error-page") {
		res = append(res, map[string]any{
			"errorCode":     page.ChildText("error-code"),
			"exceptionType": page.ChildText("exception-type"),
			"location":      page.ChildText("location"),
		})
	}
	return res
}

func parseSecurityConstraints(root *Node) []map[string]any {
	res := []map[string]any{}
	for _, sc := range root.Elements("security-constraint") {
		collections := []any{}
		for _, wrc := range sc.Elements("web-resource-collection") {
			collections = append(collections, map[string]any{
				"name":                wrc.ChildText("web-resource-name"),
				"urlPatterns":         childTexts(wrc, "url-pattern"),
				"httpMethods":         childTexts(wrc, "http-method"),
				"httpMethodOmissions": childTexts(wrc, "http-method-omission"),
			})
		}

		entry := map[string]any{
			"displayName":            sc.ChildText("display-name"),
			"webResourceCollections": collections,
		}

		// An <auth-constraint> with no <role-name> denies every role, which is
		// a different statement from having no <auth-constraint> at all. Keep
		// the two distinguishable: absent stays null.
		if ac := sc.Element("auth-constraint"); ac != nil {
			entry["authConstraint"] = map[string]any{
				"roleNames": childTexts(ac, "role-name"),
			}
		} else {
			entry["authConstraint"] = nil
		}

		if udc := sc.Element("user-data-constraint"); udc != nil {
			entry["userDataConstraint"] = map[string]any{
				"transportGuarantee": udc.ChildText("transport-guarantee"),
			}
		} else {
			entry["userDataConstraint"] = nil
		}

		res = append(res, entry)
	}
	return res
}

func parseLoginConfig(root *Node) map[string]any {
	res := map[string]any{}
	lc := root.Element("login-config")
	if lc == nil {
		return res
	}
	res["authMethod"] = lc.ChildText("auth-method")
	res["realmName"] = lc.ChildText("realm-name")
	if flc := lc.Element("form-login-config"); flc != nil {
		res["formLoginPage"] = flc.ChildText("form-login-page")
		res["formErrorPage"] = flc.ChildText("form-error-page")
	}
	return res
}

func parseServlets(root *Node) []map[string]any {
	mappings := collectMappings(root, "servlet-mapping", "servlet-name")

	res := []map[string]any{}
	for _, s := range root.Elements("servlet") {
		name := s.ChildText("servlet-name")
		entry := map[string]any{
			"name":          name,
			"class":         s.ChildText("servlet-class"),
			"jspFile":       s.ChildText("jsp-file"),
			"loadOnStartup": s.ChildText("load-on-startup"),
			"initParams":    initParams(s),
			"urlPatterns":   mappings[name],
		}
		if entry["urlPatterns"] == nil {
			entry["urlPatterns"] = []any{}
		}
		res = append(res, entry)
	}
	return res
}

func parseFilters(root *Node) []map[string]any {
	mappings := collectMappings(root, "filter-mapping", "filter-name")

	res := []map[string]any{}
	for _, f := range root.Elements("filter") {
		name := f.ChildText("filter-name")
		entry := map[string]any{
			"name":        name,
			"class":       f.ChildText("filter-class"),
			"initParams":  initParams(f),
			"urlPatterns": mappings[name],
		}
		if entry["urlPatterns"] == nil {
			entry["urlPatterns"] = []any{}
		}
		res = append(res, entry)
	}
	return res
}

// initParams returns the <init-param> children as a list rather than a map.
// A descriptor may declare the same parameter name twice, and a map would
// silently keep only one of them — precisely the collapse this resource
// exists to avoid.
func initParams(node *Node) []any {
	res := []any{}
	for _, p := range node.Elements("init-param") {
		res = append(res, map[string]any{
			"name":  p.ChildText("param-name"),
			"value": p.ChildText("param-value"),
		})
	}
	return res
}

func collectMappings(root *Node, elem string, nameElem string) map[string][]any {
	res := map[string][]any{}
	for _, m := range root.Elements(elem) {
		name := m.ChildText(nameElem)
		if name == "" {
			continue
		}
		res[name] = append(res[name], childTexts(m, "url-pattern")...)
	}
	return res
}

func childTexts(node *Node, name string) []any {
	res := []any{}
	for _, child := range node.Elements(name) {
		res = append(res, child.Text)
	}
	return res
}
