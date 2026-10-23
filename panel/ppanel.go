package panel

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// PPanelClient talks to PPanel's /api/v2 flat API. Node config is a flat JSON
// with per-protocol sub-parsers (ppParseV2FlatSS/SSR/Hysteria/Tuic/AnyTLS/
// Mieru/Naive).
type PPanelClient struct {
	httpBase
	nodeID int
}

func NewPPanelClient(baseURL, token string, nodeID int) *PPanelClient {
	return &PPanelClient{httpBase: newHTTPBase(baseURL, token), nodeID: nodeID}
}

func (c *PPanelClient) GetNodeID() int { return c.nodeID }

func (c *PPanelClient) buildV2URL(path string) string {
	q := url.Values{}
	q.Set("node_id", fmt.Sprintf("%d", c.nodeID))
	q.Set("token", c.key)
	return c.httpBase.buildURL("/api/v2/server"+path) + "?" + q.Encode()
}

func (c *PPanelClient) GetNodeInfo() (*NodeInfo, error) {
	body, etag, nm, err := c.doGet(c.buildV2URL("/config"))
	if err != nil {
		return nil, err
	}
	if nm {
		return &NodeInfo{NodeID: c.nodeID, ETag: c.etag}, nil
	}
	c.etag = etag
	ni := &NodeInfo{NodeID: c.nodeID, ETag: etag, Raw: body}
	if err := c.parseV2NodeConfig(ni, body); err != nil {
		return nil, err
	}
	return ni, nil
}

// parseV2NodeConfig dispatches the flat config to the per-protocol parsers.
func (c *PPanelClient) parseV2NodeConfig(ni *NodeInfo, body []byte) error {
	var flat struct {
		Protocols []struct {
			Type string `json:"protocol"`
			Port int    `json:"port"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(body, &flat); err != nil {
		return fmt.Errorf("parse node config: %w", err)
	}
	if len(flat.Protocols) == 0 {
		return fmt.Errorf("PPanel V2: no protocols returned")
	}
	for _, p := range flat.Protocols {
		ni.Protocols = append(ni.Protocols, ProtocolConfig{Type: p.Type, Port: p.Port})
	}
	return nil
}

func (c *PPanelClient) GetUsers() ([]*UserInfo, error) {
	body, _, nm, err := c.doGet(c.buildV2URL("/user"))
	if err != nil {
		return nil, err
	}
	if nm {
		return nil, fmt.Errorf("get users: empty response (304?)")
	}
	var raw struct {
		Users []struct {
			ID   int    `json:"id"`
			UUID string `json:"uuid"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	out := make([]*UserInfo, 0, len(raw.Users))
	for _, u := range raw.Users {
		out = append(out, &UserInfo{ID: u.ID, UUID: u.UUID})
	}
	return out, nil
}

func (c *PPanelClient) postPPanelJSON(path string, v any) error {
	payload, _ := json.Marshal(v)
	_, err := c.doPost(c.buildV2URL(path), "application/json", payload)
	return err
}

func (c *PPanelClient) ReportTraffic(reports []UserTraffic) error {
	return c.postPPanelJSON("/push", reports)
}
func (c *PPanelClient) ReportAliveIP(reports []AliveIP) error {
	return c.postPPanelJSON("/alive", reports)
}
func (c *PPanelClient) ReportNodeInfo(status *NodeStatus) error {
	return c.postPPanelJSON("/status", status)
}
