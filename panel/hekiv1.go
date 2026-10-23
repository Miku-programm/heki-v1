package panel

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// errNotModified is returned by GetUsers on a 304 (the caller keeps its last
// known user set).
var errNotModified = errors.New("heki-v1: not modified (304)")

// HekiV1Client implements heki's own public, versioned control-plane WebAPI
// ("type=heki-v1"). It is the native heki panel protocol — not an SSPanel/XBoard
// shim — and follows the published spec exactly:
//
//	GET  /api/v1/nodes/{id}             -> node config   ({"data": <node>})
//	GET  /api/v1/nodes/{id}/users       -> user list     ({"data": [<user>...]})
//	POST /api/v1/nodes/{id}/traffic     -> {"records":[{"user_id","u","d"}]}
//	POST /api/v1/nodes/{id}/alive-ips   -> {"records":[{"user_id","ips":[...]}]}
//	POST /api/v1/nodes/{id}/status      -> node status heartbeat
//
// Auth is Bearer (Authorization: Bearer <panel_key>); GETs use ETag/If-None-Match
// and may return 304; POSTs accept 200 or 204. Every request carries
// Accept: application/json, application/problem+json, User-Agent: heki and
// X-Heki-Node-Id. Errors use RFC 7807 (application/problem+json).
//
// Spec: https://hekicore.github.io/heki-docs/#/panel/heki-v1-webapi
type HekiV1Client struct {
	httpBase
	nodeID            int
	requestedProtocol string // X-Heki-Requested-Protocol hint (local server_type)
}

func NewHekiV1Client(baseURL, token string, nodeID int) *HekiV1Client {
	return &HekiV1Client{httpBase: newHTTPBase(baseURL, token), nodeID: nodeID}
}

// SetRequestedProtocol sets the X-Heki-Requested-Protocol hint (the local
// server_type). Optional — the API's returned protocol is authoritative.
func (c *HekiV1Client) SetRequestedProtocol(p string) { c.requestedProtocol = p }

func (c *HekiV1Client) GetNodeID() int { return c.nodeID }

func (c *HekiV1Client) nodeURL(suffix string) string {
	return c.buildURL(fmt.Sprintf("/api/v1/nodes/%d%s", c.nodeID, suffix))
}

func (c *HekiV1Client) setHeaders(req *http.Request) {
	if c.key != "" {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Accept", "application/json, application/problem+json")
	req.Header.Set("User-Agent", "heki")
	req.Header.Set("X-Heki-Node-Id", strconv.Itoa(c.nodeID))
	if c.requestedProtocol != "" {
		req.Header.Set("X-Heki-Requested-Protocol", c.requestedProtocol)
	}
}

// hekiGet issues a GET, returns the unwrapped `data` value (or the raw body when
// there is no envelope — a documented compat behavior), and notModified on 304.
func (c *HekiV1Client) hekiGet(url string) (data json.RawMessage, notModified bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	c.setHeaders(req)
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return nil, true, nil
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, false, fmt.Errorf("GET %s: %w", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("GET %s: HTTP %d: %s", url, resp.StatusCode, problemDetail(b))
	}
	if et := resp.Header.Get("ETag"); et != "" {
		c.etag = et
	}
	return unwrapData(b), false, nil
}

// hekiPost sends a JSON body; it accepts any 2xx (200/204).
func (c *HekiV1Client) hekiPost(url string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("POST %s: HTTP %d: %s", url, resp.StatusCode, problemDetail(b))
	}
	return nil
}

// --- GET /api/v1/nodes/{id} ---

func (c *HekiV1Client) GetNodeInfo() (*NodeInfo, error) {
	data, nm, err := c.hekiGet(c.nodeURL(""))
	if err != nil {
		return nil, err
	}
	if nm {
		return &NodeInfo{NodeID: c.nodeID, ETag: c.etag}, nil
	}
	var n struct {
		Protocol string `json:"protocol"`
		Listen   struct {
			Port int    `json:"port"`
			IP   string `json:"ip"`
		} `json:"listen"`
		Limits struct {
			SpeedMbps   float64 `json:"speed_mbps"`
			TrafficRate float64 `json:"traffic_rate"`
		} `json:"limits"`
		Scheduler struct {
			PullIntervalSeconds int `json:"pull_interval_seconds"`
			PushIntervalSeconds int `json:"push_interval_seconds"`
		} `json:"scheduler"`
		Security struct {
			Mode       string `json:"mode"`
			ServerName string `json:"server_name"`
			Reality    struct {
				PrivateKey  string   `json:"private_key"`
				ServerName  string   `json:"server_name"`
				ServerNames []string `json:"server_names"`
				ShortID     string   `json:"short_id"`
				ShortIDs    []string `json:"short_ids"`
				Dest        string   `json:"dest"`
			} `json:"reality"`
		} `json:"security"`
		ProtocolSettings map[string]any `json:"protocol_settings"`
	}
	if err := json.Unmarshal(data, &n); err != nil {
		return nil, fmt.Errorf("parse node: %w", err)
	}
	ni := &NodeInfo{
		NodeID:          c.nodeID,
		ETag:            c.etag,
		Raw:             data,
		Protocol:        canonicalProtocol(n.Protocol),
		SpeedLimit:      int(n.Limits.SpeedMbps),
		TrafficRate:     n.Limits.TrafficRate,
		ListenIP:        n.Listen.IP,
		ListenPort:      n.Listen.Port,
		PullIntervalSec: n.Scheduler.PullIntervalSeconds,
		PushIntervalSec: n.Scheduler.PushIntervalSeconds,
		SecurityMode:    n.Security.Mode,
		ServerName:      n.Security.ServerName,
	}
	if n.Protocol != "" || n.Listen.Port != 0 {
		ni.Protocols = []ProtocolConfig{{Type: ni.Protocol, Port: n.Listen.Port, Settings: n.ProtocolSettings}}
	}
	if n.Security.Mode == "reality" {
		r := &RealityInfo{
			PrivateKey:  n.Security.Reality.PrivateKey,
			ServerNames: n.Security.Reality.ServerNames,
			ShortIDs:    n.Security.Reality.ShortIDs,
			Dest:        n.Security.Reality.Dest,
		}
		if len(r.ServerNames) == 0 && n.Security.Reality.ServerName != "" {
			r.ServerNames = []string{n.Security.Reality.ServerName}
		}
		if len(r.ShortIDs) == 0 && n.Security.Reality.ShortID != "" {
			r.ShortIDs = []string{n.Security.Reality.ShortID}
		}
		ni.Reality = r
	}
	return ni, nil
}

// --- GET /api/v1/nodes/{id}/users ---

func (c *HekiV1Client) GetUsers() ([]*UserInfo, error) {
	data, nm, err := c.hekiGet(c.nodeURL("/users"))
	if err != nil {
		return nil, err
	}
	if nm {
		// 304: caller keeps its last known user set.
		return nil, errNotModified
	}
	var raw []struct {
		ID             int     `json:"id"`
		UUID           string  `json:"uuid"`
		Password       string  `json:"password"`
		Method         string  `json:"method"`
		Port           int     `json:"port"`
		Protocol       string  `json:"protocol"`
		ProtocolParam  string  `json:"protocol_param"`
		Obfs           string  `json:"obfs"`
		ObfsParam      string  `json:"obfs_param"`
		SpeedLimitMbps float64 `json:"speed_limit_mbps"`
		DeviceLimit    int     `json:"device_limit"`
		UploadBytes    int64   `json:"upload_bytes"`
		DownloadBytes  int64   `json:"download_bytes"`
		TransferEnable int64   `json:"transfer_enable_bytes"`
		ExpiredAtUnix  int64   `json:"expired_at_unix"`
		Banned         bool    `json:"banned"`
		Enabled        *bool   `json:"enabled"`
		Disabled       bool    `json:"disabled"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	out := make([]*UserInfo, 0, len(raw))
	for _, u := range raw {
		// A user is active unless banned, disabled, or enabled==false.
		if u.Banned || u.Disabled || (u.Enabled != nil && !*u.Enabled) {
			continue
		}
		out = append(out, &UserInfo{
			ID:             u.ID,
			UUID:           u.UUID,
			Password:       u.Password,
			Method:         u.Method,
			Port:           u.Port,
			Protocol:       u.Protocol,
			ProtocolParam:  u.ProtocolParam,
			Obfs:           u.Obfs,
			ObfsParam:      u.ObfsParam,
			SpeedLimit:     int(u.SpeedLimitMbps),
			DeviceLimit:    u.DeviceLimit,
			UploadBytes:    u.UploadBytes,
			DownloadBytes:  u.DownloadBytes,
			TransferEnable: u.TransferEnable,
			ExpiredAt:      u.ExpiredAtUnix,
		})
	}
	return out, nil
}

// --- POST /api/v1/nodes/{id}/traffic ---

type trafficRecord struct {
	UserID int   `json:"user_id"`
	U      int64 `json:"u"`
	D      int64 `json:"d"`
}

func (c *HekiV1Client) ReportTraffic(reports []UserTraffic) error {
	if len(reports) == 0 {
		return nil
	}
	recs := make([]trafficRecord, 0, len(reports))
	for _, r := range reports {
		recs = append(recs, trafficRecord{UserID: r.UserID, U: r.Upload, D: r.Download})
	}
	return c.hekiPost(c.nodeURL("/traffic"), map[string]any{"records": recs})
}

// --- POST /api/v1/nodes/{id}/alive-ips ---

type aliveIPRecord struct {
	UserID int      `json:"user_id"`
	IPs    []string `json:"ips"`
}

func (c *HekiV1Client) ReportAliveIP(reports []AliveIP) error {
	if len(reports) == 0 {
		return nil
	}
	// The spec groups IPs per user; aggregate the flat records.
	byUser := map[int][]string{}
	order := []int{}
	for _, r := range reports {
		if _, ok := byUser[r.UserID]; !ok {
			order = append(order, r.UserID)
		}
		byUser[r.UserID] = append(byUser[r.UserID], r.IP)
	}
	recs := make([]aliveIPRecord, 0, len(order))
	for _, id := range order {
		recs = append(recs, aliveIPRecord{UserID: id, IPs: byUser[id]})
	}
	return c.hekiPost(c.nodeURL("/alive-ips"), map[string]any{"records": recs})
}

// --- POST /api/v1/nodes/{id}/status ---

func (c *HekiV1Client) ReportNodeInfo(status *NodeStatus) error {
	if status == nil {
		return nil
	}
	body := map[string]any{
		"reported_at":    time.Now().UTC().Format(time.RFC3339),
		"cpu_percent":    status.CPU,
		"uptime_seconds": status.Uptime,
		"load": map[string]any{
			"one":     status.Load,
			"five":    status.Load,
			"fifteen": status.Load,
		},
		"memory": map[string]any{
			"used_bytes": int64(status.Mem),
		},
	}
	return c.hekiPost(c.nodeURL("/status"), body)
}

// unwrapData returns the inner value of a {"data": ...} envelope, falling back
// to the raw body when there is no envelope (documented compat behavior).
func unwrapData(b []byte) json.RawMessage {
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(b, &env); err == nil && len(env.Data) > 0 {
		return env.Data
	}
	return b
}

// problemDetail extracts an RFC 7807 detail/title for error messages.
func problemDetail(b []byte) string {
	var p struct {
		Title  string `json:"title"`
		Detail string `json:"detail"`
	}
	if json.Unmarshal(b, &p) == nil {
		if p.Detail != "" {
			return p.Detail
		}
		if p.Title != "" {
			return p.Title
		}
	}
	s := string(b)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

// canonicalProtocol maps the heki-v1 compat aliases onto heki's canonical names.
func canonicalProtocol(p string) string {
	switch p {
	case "v2ray":
		return "vmess"
	case "shadowsocks":
		return "ss"
	case "shadowsocksr":
		return "ssr"
	case "hysteria", "hysteria2":
		return "hysteria2"
	default:
		return p
	}
}
