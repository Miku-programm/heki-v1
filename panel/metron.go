package panel

import (
	"encoding/json"
	"fmt"
)

// MetronClient talks to the Metron panel. Its responses are normalized into the
// common NodeInfo/UserInfo shape (metron_normalize).
type MetronClient struct {
	httpBase
	nodeID int
}

func NewMetronClient(baseURL, token string, nodeID int) *MetronClient {
	return &MetronClient{httpBase: newHTTPBase(baseURL, token), nodeID: nodeID}
}

func (c *MetronClient) GetNodeID() int { return c.nodeID }

func (c *MetronClient) metronURL(path string) string {
	return c.buildURL(fmt.Sprintf("/api/metron%s?node_id=%d&token=%s", path, c.nodeID, c.key))
}

func (c *MetronClient) GetNodeInfo() (*NodeInfo, error) {
	body, etag, nm, err := c.doGet(c.metronURL("/node"))
	if err != nil {
		return nil, err
	}
	if nm {
		return &NodeInfo{NodeID: c.nodeID, ETag: c.etag}, nil
	}
	c.etag = etag
	ni := &NodeInfo{NodeID: c.nodeID, ETag: etag, Raw: body}
	metronNormalizeNode(ni, body)
	return ni, nil
}

// metronNormalizeNode maps Metron's field names onto the common NodeInfo.
func metronNormalizeNode(ni *NodeInfo, body []byte) {
	var raw struct {
		Speed int `json:"speed_limit"`
		Port  int `json:"port"`
		Proto string `json:"protocol"`
	}
	if json.Unmarshal(body, &raw) == nil {
		ni.SpeedLimit = raw.Speed
		if raw.Proto != "" {
			ni.Protocols = []ProtocolConfig{{Type: raw.Proto, Port: raw.Port}}
		}
	}
}

func (c *MetronClient) GetUsers() ([]*UserInfo, error) {
	body, _, nm, err := c.doGet(c.metronURL("/users"))
	if err != nil {
		return nil, err
	}
	if nm {
		return nil, fmt.Errorf("get users: empty response (304?)")
	}
	var raw []struct {
		ID   int    `json:"id"`
		UUID string `json:"uuid"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	out := make([]*UserInfo, 0, len(raw))
	for _, u := range raw {
		out = append(out, &UserInfo{ID: u.ID, UUID: u.UUID})
	}
	return out, nil
}

func (c *MetronClient) ReportTraffic(reports []UserTraffic) error {
	payload, _ := json.Marshal(reports)
	_, err := c.doPost(c.metronURL("/traffic"), "application/json", payload)
	return err
}
func (c *MetronClient) ReportAliveIP(reports []AliveIP) error {
	payload, _ := json.Marshal(reports)
	_, err := c.doPost(c.metronURL("/aliveip"), "application/json", payload)
	return err
}
func (c *MetronClient) ReportNodeInfo(status *NodeStatus) error {
	payload, _ := json.Marshal(status)
	_, err := c.doPost(c.metronURL("/status"), "application/json", payload)
	return err
}
