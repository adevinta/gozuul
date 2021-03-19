/*
Copyright 2019 Adevinta
*/

package gozuul

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/julienschmidt/httprouter"
)

var testCasesArgsPScan = []struct {
	name             string
	skip, skipAlways bool
	nilError         bool
	target           string
}{
	{
		name:     "emptyTarget",
		nilError: false,
		target:   "",
	}, {
		name:     "targetNotExists",
		nilError: false,
		target:   "http://test.example.com",
	}, {
		name:     "notValidURL",
		nilError: false,
		target:   "htfewp://test.e::xam:ple.com",
	},
}

var testCasesPScan = []struct {
	name             string
	skip, skipAlways bool
	f                http.HandlerFunc
	nilError         bool
	prevEnabled      bool
	adminDisabled    bool
	vulnerable       bool
	mightVulnerable  bool
}{
	{
		name:            "forbidden",
		f:               forbidden,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   true,
		vulnerable:      false,
		mightVulnerable: false,
	}, {
		name:            "vulnerable",
		f:               vulnerable,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      true,
		mightVulnerable: false,
	}, {
		name:            "notFound",
		f:               notFound,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
	}, {
		name:            "internalServerError",
		f:               internalServerError,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
	}, {
		name:            "badRequest",
		f:               badRequest,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
	}, {
		name:            "statusOK",
		f:               ok,
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
	},
}

func vulnerable(w http.ResponseWriter, r *http.Request) {
	http.Error(w, fmt.Sprintf("contains the Dork that makes it vulnerable: %s Yiha!!!!", vulnerableDork), 400)
}

func ok(w http.ResponseWriter, r *http.Request) {
}

func found(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Location", "http://donotfollow.example.com")
	http.Error(w, "", 302)
}

func forbidden(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", 403)
}

func notFound(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", 404)
}

func internalServerError(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", 500)
}

func badRequest(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "", 400)
}

func TestPassiveScan(t *testing.T) {
	// Test all the test cases defined in testCasesArgsPScan
	for _, tc := range testCasesArgsPScan {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			_, err := PassiveScan(tc.target)
			if tc.nilError && err != nil {
				t.Errorf("nil error expected, got  %v", err)
			} else if !tc.nilError && err == nil {
				t.Errorf("error expected, got  %v", err)
			}
		})
	}

	// Test all the test cases defined in testCasesPScan
	for _, tc := range testCasesPScan {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			ts := httptest.NewServer(tc.f)
			defer ts.Close()

			rs, err := PassiveScan(ts.URL)
			if (tc.nilError && err != nil) || (!tc.nilError && err == nil) {
				t.Errorf("(%v) nilError expected: %v, got error: %v", tc.name, tc.nilError, err)
			}
			if tc.prevEnabled != rs.PrevEnabled {
				t.Errorf("(%v) prevEnabled expected: %v, got: %v", tc.name, tc.prevEnabled, rs.PrevEnabled)
			}
			if tc.adminDisabled != rs.AdminDisabled {
				t.Errorf("(%v) adminDisabled expected: %v, got: %v", tc.name, tc.adminDisabled, rs.AdminDisabled)
			}
			if tc.vulnerable != rs.Vulnerable {
				t.Errorf("(%v) vulnerable expected: %v, got: %v", tc.name, tc.vulnerable, rs.Vulnerable)
			}
			if tc.mightVulnerable != rs.MightVulnerable {
				t.Errorf("(%v) mightVulnerable expected: %v, got: %v", tc.name, tc.mightVulnerable, rs.MightVulnerable)
			}
		})
	}
}

var testCasesArgsAScan = []struct {
	name             string
	skip, skipAlways bool
	nilError         bool
	target           string
	callback         string
	cbackChan        chan bool
}{
	{
		name:      "emptyTarget",
		nilError:  false,
		target:    "",
		cbackChan: make(chan bool, 1),
	}, {
		name:      "targetNotExists",
		nilError:  false,
		target:    "http://test.example.com",
		cbackChan: make(chan bool, 1),
	}, {
		name:      "notValidURL",
		nilError:  false,
		target:    "htfewp://test.e::xam:ple.com",
		cbackChan: make(chan bool, 1),
	}, {
		name:     "nilChannel",
		nilError: false,
		target:   "http://test.example.com",
	}, {
		name:      "unbufferedChannel",
		nilError:  false,
		target:    "http://test.example.com",
		cbackChan: make(chan bool),
	},
}

type route struct {
	path    string
	method  string
	handler httprouter.Handle
}

var testCasesAScan = []struct {
	name             string
	skip, skipAlways bool
	funcs            []route
	nilError         bool
	callbackRec      bool
	prevEnabled      bool
	adminDisabled    bool
	vulnerable       bool
	mightVulnerable  bool
}{
	{
		name: "vulnFilterEnabled",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: vulnFilterEnabled,
			},
		},
		nilError:        true,
		prevEnabled:     true,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "vulnerable",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: toggleFilterEnabled, // Toggle from not enabled to enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: incrementingFilters, // Revision of filters increment at each call.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: adaptHandler(found), // setFilter and filter upload seem to succed.
			},
		},
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      true,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "mightVulnerable",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: adaptHandler(ok), // No filters yet.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: mightVulnerable, // Returns 500 with Cassandra Dork.
			},
		},
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: true,
		callbackRec:     false,
	}, {
		name: "adminDisabled",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: adaptHandler(ok), // No filters yet.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: adaptHandler(forbidden),
			},
		},
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   true,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "callbackReceived",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: adaptHandler(ok), // No filters yet.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: adaptHandler(found), // Filter and filter upload seem to succed.
			},
		},
		nilError:        true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      true,
		mightVulnerable: false,
		callbackRec:     true,
	}, {
		name: "filterEndpointNotExists",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound),
			},
		},
		nilError:        false,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "badFilterHref",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: badHref,
			},
		},
		nilError:        false,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "badFilterRev",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: badRev,
			},
		},
		nilError:        false,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "filterDoesNotEnable",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: incrementingFilters, // Revision of filters increment at each call.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: adaptHandler(found), // Filter and filter upload seem to succed.
			},
		},
		nilError:        false,
		skip:            true,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "revisionNotUpdated",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: adaptHandler(notFound), // Filter not previously enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: adaptHandler(ok), // Revision of filters doens't increment.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: adaptHandler(found), // Filter and filter upload seem to succed.
			},
		},
		nilError:        false,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	}, {
		name: "errorSettingFilter",
		funcs: []route{
			route{
				path:    vcheckEndpoint,
				method:  "GET",
				handler: toggleFilterEnabled, // Toggle from not enabled to enabled.
			},
			route{
				path:    filtersEndpoint,
				method:  "GET",
				handler: incrementingFilters, // Revision of filters increment at each call.
			},
			route{
				path:    "/admin/scriptmanager",
				method:  "POST",
				handler: badFilterUpdate, // Filter and filter upload seem to succed.
			},
		},
		nilError:        false,
		prevEnabled:     false,
		adminDisabled:   false,
		vulnerable:      false,
		mightVulnerable: false,
		callbackRec:     false,
	},
}

var (
	enabled bool = false
	revInc  int  = 0
)

const (
	vcheckFilter string = "<td><a id=1 href=scriptmanager?action=DOWNLOAD&filter_id=origin:Vulncheck:pre&revision=%v>DOWNLOAD</a></td>"
	dummyFilter  string = "<td><a id=2 href=scriptmanager?action=DOWNLOAD&filter_id=dummy&revision=%v>DOWNLOAD</a></td>"
	otherFilter  string = "<td><a id=3 href=scriptmanager?action=DOWNLOAD&filter_id=other&revision=%v>DOWNLOAD</a></td>"
)

func clearGlobals() {
	enabled = false
	revInc = 0
}

func adaptHandler(fn http.HandlerFunc) httprouter.Handle {
	return func(w http.ResponseWriter, req *http.Request, _ httprouter.Params) {
		fn(w, req)
	}
}

func vulnFilterEnabled(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, "vulnerable")
}

func toggleFilterEnabled(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if enabled {
		fmt.Fprint(w, "vulnerable")
	}

	enabled = !enabled
}

func incrementingFilters(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	vf := fmt.Sprintf(vcheckFilter, 1+revInc)
	vf2 := fmt.Sprintf(vcheckFilter, 2+revInc)
	df := fmt.Sprintf(dummyFilter, 3+revInc)
	of := fmt.Sprintf(otherFilter, 1+revInc)

	// Could overflow if executed max int times in a test session...
	revInc++

	fmt.Fprint(w, vf)
	fmt.Fprint(w, vf2)
	fmt.Fprint(w, df)
	fmt.Fprint(w, of)
}

func badRev(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	br := fmt.Sprintf(vcheckFilter, "NaN")
	fmt.Fprint(w, br)
}

func badHref(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	fmt.Fprint(w, `<td><a href=":">DOWNLOAD</a>`)
}

func mightVulnerable(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	http.Error(w, fmt.Sprintf("contains the Dork that makes it possibly vulnerable: %s", cassandraDork), 500)
}

func badFilterUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	values := r.URL.Query()
	if action, ok := values["action"]; ok && action[0] == "UPLOAD" {
		w.Header().Set("Location", "http://donotfollow.example.com")
		http.Error(w, "", 302)
		return
	}
	http.Error(w, "", 500)
}

func TestActiveScan(t *testing.T) {
	// Test all the test cases defined in testCasesArgsAScan
	for _, tc := range testCasesArgsAScan {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}

			_, err := ActiveScan(tc.target, tc.callback, tc.cbackChan)
			if tc.nilError && err != nil {
				t.Errorf("nil error expected, got  %v", err)
			} else if !tc.nilError && err == nil {
				t.Errorf("error expected, got  %v", err)
			}
		})
	}

	// Test all the test cases defined in testCasesAScan
	for _, tc := range testCasesAScan {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			if testing.Short() && tc.skip || tc.skipAlways {
				t.SkipNow()
			}
			clearGlobals()

			mux := httprouter.New()
			for _, f := range tc.funcs {
				mux.Handle(f.method, f.path, f.handler)
			}
			ts := httptest.NewServer(mux)
			defer ts.Close()

			cbc := make(chan bool, 1)
			if tc.callbackRec {
				cbc <- true
			}

			rs, err := ActiveScan(ts.URL, "", cbc)
			if (tc.nilError && err != nil) || (!tc.nilError && err == nil) {
				t.Errorf("(%v) nilError expected: %v, got error: %v", tc.name, tc.nilError, err)
			}
			if tc.prevEnabled != rs.PrevEnabled {
				t.Errorf("(%v) prevEnabled expected: %v, got: %v", tc.name, tc.prevEnabled, rs.PrevEnabled)
			}
			if tc.adminDisabled != rs.AdminDisabled {
				t.Errorf("(%v) adminDisabled expected: %v, got: %v", tc.name, tc.adminDisabled, rs.AdminDisabled)
			}
			if tc.vulnerable != rs.Vulnerable {
				t.Errorf("(%v) vulnerable expected: %v, got: %v", tc.name, tc.vulnerable, rs.Vulnerable)
			}
			if tc.mightVulnerable != rs.MightVulnerable {
				t.Errorf("(%v) mightVulnerable expected: %v, got: %v", tc.name, tc.mightVulnerable, rs.MightVulnerable)
			}
		})
	}
}
