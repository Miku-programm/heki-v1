package panel

import (
	"encoding/json"
	"fmt"
)

// HekiV1Client talks to heki's own panel ("hekiv1"), which uses ETag conditional
// GETs and an apply* protocol mapping. Auth is a bearer-style token header.
type HekiV1Client struct {
	httpBase
	nodeID int
}

func NewHekiV1Client(baseURL, token string, nodeID int) *HekiV1Client {
	return &HekiV1Client{httpBase: newHTTPBase(baseURL, token), nodeID: nodeID}
}

func (c *HekiV1Client) GetNodeID() int { return c.nodeID }

func (c *HekiV1Client) hekiURL(path string) string {
	return c.buildURL(fmt.Sprintf("/api/v1/node/%d%s", c.nodeID, path))
}

func (c *HekiV1Client) GetNodeInfo() (*NodeInfo, error) {
	body, etag, nm, err := c.doGet(c.hekiURL("/config"))
	if err != nil {
		return nil, err
	}
	if nm {
		return &NodeInfo{NodeID: c.nodeID, ETag: c.etag}, nil
	}
	c.etag = etag
	ni := &NodeInfo{NodeID: c.nodeID, ETag: etag, Raw: body}
	var raw struct {
		SpeedLimit int `json:"speed_limit"`
		Protocols  []struct {
			Type string `json:"type"`
			Port int    `json:"port"`
		} `json:"protocols"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse node config: %w", err)
	}
	ni.SpeedLimit = raw.SpeedLimit
	for _, p := range raw.Protocols {
		ni.Protocols = append(ni.Protocols, ProtocolConfig{Type: p.Type, Port: p.Port})
	}
	return ni, nil
}

func (c *HekiV1Client) GetUsers() ([]*UserInfo, error) {
	body, _, nm, err := c.doGet(c.hekiURL("/users"))
	if err != nil {
		return nil, err
	}
	if nm {
		return nil, fmt.Errorf("get users: empty response (304?)")
	}
	var raw []struct {
		ID     int    `json:"id"`
		Email  string `json:"email"`
		UUID   string `json:"uuid"`
		Passwd string `json:"password"`
		Method string `json:"method"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	out := make([]*UserInfo, 0, len(raw))
	for _, u := range raw {
		out = append(out, &UserInfo{ID: u.ID, Email: u.Email, UUID: u.UUID, Password: u.Passwd, Method: u.Method})
	}
	return out, nil
}

func (c *HekiV1Client) ReportTraffic(reports []UserTraffic) error {
	payload, _ := json.Marshal(reports)
	_, err := c.doPost(c.hekiURL("/traffic"), "application/json", payload)
	return err
}
func (c *HekiV1Client) ReportAliveIP(reports []AliveIP) error {
	payload, _ := json.Marshal(reports)
	_, err := c.doPost(c.hekiURL("/aliveip"), "application/json", payload)
	return err
}
func (c *HekiV1Client) ReportNodeInfo(status *NodeStatus) error {
	payload, _ := json.Marshal(status)
	_, err := c.doPost(c.hekiURL("/status"), "application/json", payload)
	return err
}
