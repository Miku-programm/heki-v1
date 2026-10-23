package panel

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// httpBase is the shared HTTP plumbing for panel clients: a base URL, an auth
// key, an http.Client, and ETag tracking for conditional GETs (If-None-Match).
type httpBase struct {
	baseURL string
	key     string
	client  *http.Client

	etag string // last seen ETag for conditional requests
}

func newHTTPBase(baseURL, key string) httpBase {
	return httpBase{
		baseURL: baseURL,
		key:     key,
		client:  &http.Client{Timeout: 20 * time.Second},
	}
}

func (h *httpBase) buildURL(path string) string { return h.baseURL + path }

// doGet performs a GET with the stored ETag. It returns the body, the response
// ETag, and notModified=true on HTTP 304.
func (h *httpBase) doGet(url string) (body []byte, etag string, notModified bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", false, err
	}
	if h.etag != "" {
		req.Header.Set("If-None-Match", h.etag)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, h.etag, true, nil
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", false, fmt.Errorf("GET %s read body: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, "", false, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	return b, resp.Header.Get("ETag"), false, nil
}

// doPost performs a POST with a JSON (or form) body and returns the response body.
func (h *httpBase) doPost(url, contentType string, payload []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return b, fmt.Errorf("POST %s: HTTP %d, body: %s", url, resp.StatusCode, string(b))
	}
	return b, nil
}
