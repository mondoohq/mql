// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stmcginnis/gofish"
	"github.com/stmcginnis/gofish/schemas"
)

// serviceRoot is a recorded Redfish service root of an HPE iLO 5.
const serviceRoot = `{
  "@odata.id": "/redfish/v1/",
  "@odata.type": "#ServiceRoot.v1_5_2.ServiceRoot",
  "Id": "RootService",
  "Name": "HPE RESTful Root Service",
  "RedfishVersion": "1.6.0",
  "Managers": {"@odata.id": "/redfish/v1/Managers/"},
  "Systems": {"@odata.id": "/redfish/v1/Systems/"}
}`

// unauthorizedBody is the error document a controller returns when it requires
// credentials for the service root.
const unauthorizedBody = `{
  "error": {
    "code": "Base.1.4.GeneralError",
    "message": "A general error has occurred. See ExtendedInfo for more information."
  }
}`

func TestLooksLikeServiceRoot(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "recorded service root", body: serviceRoot, want: true},
		{
			name: "odata type only",
			body: `{"@odata.type":"#ServiceRoot.v1_1_0.ServiceRoot"}`,
			want: true,
		},
		{name: "odata id only", body: `{"@odata.id":"/redfish/v1/"}`, want: true},
		{name: "error document", body: unauthorizedBody},
		{name: "other resource", body: `{"@odata.id":"/redfish/v1/Managers/1"}`},
		{name: "html login page", body: `<html><body>Login</body></html>`},
		{name: "empty body"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := looksLikeServiceRoot([]byte(tt.body)); got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServiceRootAnswersAnonymously(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		want    bool
		headers map[string]string
	}{
		{name: "open service root", status: http.StatusOK, body: serviceRoot, want: true},
		{name: "credentials required", status: http.StatusUnauthorized, body: unauthorizedBody},
		{name: "forbidden", status: http.StatusForbidden, body: unauthorizedBody},
		{name: "error document with 200", status: http.StatusOK, body: unauthorizedBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotPath string
			var gotAuth string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotAuth = r.Header.Get("Authorization")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			got, err := serviceRootAnswersAnonymously(srv.Client(), srv.URL)
			if err != nil {
				t.Fatalf("serviceRootAnswersAnonymously() error = %v", err)
			}
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
			if gotPath != ServiceRootPath {
				t.Errorf("requested %q, want %q", gotPath, ServiceRootPath)
			}
			if gotAuth != "" {
				t.Errorf("probe sent an Authorization header %q, want none", gotAuth)
			}
		})
	}
}

func TestServiceRootAnswersAnonymouslyTrimsEndpoint(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(serviceRoot))
	}))
	defer srv.Close()

	if _, err := serviceRootAnswersAnonymously(srv.Client(), srv.URL+"/"); err != nil {
		t.Fatalf("serviceRootAnswersAnonymously() error = %v", err)
	}
	if gotPath != ServiceRootPath {
		t.Errorf("requested %q, want %q", gotPath, ServiceRootPath)
	}
}

func TestServiceRootAnswersAnonymouslyReportsTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	endpoint := srv.URL
	client := srv.Client()
	srv.Close()

	// A controller the probe cannot reach must surface an error rather than a
	// false, so the resource can resolve to null instead of claiming the
	// service root is closed.
	if _, err := serviceRootAnswersAnonymously(client, endpoint); err == nil {
		t.Error("serviceRootAnswersAnonymously() returned no error for an unreachable host")
	}
}

func TestClassifyGetError(t *testing.T) {
	tests := []struct {
		name         string
		err          error
		wantNotFound bool
	}{
		{
			name:         "not found",
			err:          &schemas.Error{HTTPReturnedStatusCode: http.StatusNotFound},
			wantNotFound: true,
		},
		{
			name:         "not implemented",
			err:          &schemas.Error{HTTPReturnedStatusCode: http.StatusNotImplemented},
			wantNotFound: true,
		},
		{name: "unauthorized", err: &schemas.Error{HTTPReturnedStatusCode: http.StatusUnauthorized}},
		{name: "server error", err: &schemas.Error{HTTPReturnedStatusCode: http.StatusInternalServerError}},
		{name: "transport error", err: errors.New("connection refused")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyGetError("/redfish/v1/Managers/1", tt.err)
			if got == nil {
				t.Fatal("classifyGetError() returned no error")
			}
			if errors.Is(got, ErrNotFound) != tt.wantNotFound {
				t.Errorf("ErrNotFound = %v, want %v", errors.Is(got, ErrNotFound), tt.wantNotFound)
			}
			if !errors.Is(got, tt.err) {
				t.Error("classifyGetError() dropped the source error")
			}
		})
	}
}

func TestGetRaw(t *testing.T) {
	managerDoc := `{"@odata.id":"/redfish/v1/Managers/1","Id":"1"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case ServiceRootPath:
			_, _ = w.Write([]byte(serviceRoot))
		case "/redfish/v1/Managers/1":
			_, _ = w.Write([]byte(managerDoc))
		case "/redfish/v1/Managers/1/NetworkProtocol":
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(unauthorizedBody))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(unauthorizedBody))
		}
	}))
	defer srv.Close()

	client, err := gofish.ConnectDefault(srv.URL)
	if err != nil {
		t.Fatalf("could not connect to the test service: %v", err)
	}
	conn := &RedfishConnection{client: client}

	t.Run("returns the document", func(t *testing.T) {
		raw, err := conn.GetRaw("/redfish/v1/Managers/1")
		if err != nil {
			t.Fatalf("GetRaw() error = %v", err)
		}
		if string(raw) != managerDoc {
			t.Errorf("got %q, want %q", string(raw), managerDoc)
		}
	})

	t.Run("reports an unserved resource as not found", func(t *testing.T) {
		_, err := conn.GetRaw("/redfish/v1/Managers/1/NetworkProtocol")
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("reports other failures as errors", func(t *testing.T) {
		_, err := conn.GetRaw("/redfish/v1/Chassis")
		if err == nil {
			t.Fatal("GetRaw() returned no error")
		}
		if errors.Is(err, ErrNotFound) {
			t.Error("a server error must not read as a missing resource")
		}
	})

	t.Run("rejects an empty uri", func(t *testing.T) {
		if _, err := conn.GetRaw(""); err == nil {
			t.Error("GetRaw() accepted an empty uri")
		}
	})

	t.Run("rejects a connection without a client", func(t *testing.T) {
		empty := &RedfishConnection{}
		if _, err := empty.GetRaw("/redfish/v1/Managers/1"); err == nil {
			t.Error("GetRaw() accepted a connection without a client")
		}
	})
}

func TestServiceRootUnauthenticatedNeedsAnEndpoint(t *testing.T) {
	conn := &RedfishConnection{}
	if _, err := conn.ServiceRootUnauthenticated(); err == nil {
		t.Error("ServiceRootUnauthenticated() returned no error without an endpoint")
	}
}
