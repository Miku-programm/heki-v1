package panel

import (
	"encoding/json"
	"fmt"
	"net/url"
)

// SSPanelClient talks to SSPanel's mod_mu API. Endpoints (recovered):
//
//	GET  /mod_mu/nodes/{id}/info
//	GET  /mod_mu/users?node_id={id}
//	POST /mod_mu/users/traffic?node_id={id}
//	POST /mod_mu/users/aliveip?node_id={id}
//
// Auth is a ?key= query parameter.
type SSPanelClient struct {
	httpBase
	nodeID int
}

func NewSSPanelClient(baseURL, key string, nodeID int) *SSPanelClient {
	return &SSPanelClient{httpBase: newHTTPBase(baseURL, key), nodeID: nodeID}
}

func (c *SSPanelClient) GetNodeID() int { return c.nodeID }

func (c *SSPanelClient) withKey(path string) string {
	sep := "?"
	if u, err := url.Parse(path); err == nil && u.RawQuery != "" {
		sep = "&"
	}
	return c.buildURL(path) + sep + "key=" + url.QueryEscape(c.key)
}

func (c *SSPanelClient) GetNodeInfo() (*NodeInfo, error) {
	u := c.withKey(fmt.Sprintf("/mod_mu/nodes/%d/info", c.nodeID))
	body, etag, notModified, err := c.doGet(u)
	if err != nil {
		return nil, fmt.Errorf("parse node config: %w", err)
	}
	if notModified {
		return &NodeInfo{NodeID: c.nodeID, ETag: c.etag}, nil
	}
	c.etag = etag
	ni := &NodeInfo{NodeID: c.nodeID, ETag: etag, Raw: body}
	c.enrichSort0Or10NodeInfo(ni, body)
	return ni, nil
}

// enrichSort0Or10NodeInfo applies the SSPanel "sort" field semantics (sort 0 or
// 10 carry the protocol/port in different fields).
func (c *SSPanelClient) enrichSort0Or10NodeInfo(ni *NodeInfo, body []byte) {
	var raw struct {
		Ret  int `json:"ret"`
		Data struct {
			Sort       int    `json:"sort"`
			Server     string `json:"server"`
			SpeedLimit int    `json:"node_speedlimit"`
		} `json:"data"`
	}
	if json.Unmarshal(body, &raw) == nil {
		ni.SpeedLimit = raw.Data.SpeedLimit
	}
}

func (c *SSPanelClient) GetUsers() ([]*UserInfo, error) {
	u := c.withKey(fmt.Sprintf("/mod_mu/users?node_id=%d", c.nodeID))
	body, _, notModified, err := c.doGet(u)
	if err != nil {
		return nil, err
	}
	if notModified {
		return nil, fmt.Errorf("get users: empty response (304?)")
	}
	var raw struct {
		Ret  int `json:"ret"`
		Data []struct {
			ID         int    `json:"id"`
			Email      string `json:"email"`
			UUID       string `json:"uuid"`
			Passwd     string `json:"passwd"`
			Method     string `json:"method"`
			SpeedLimit int    `json:"node_speedlimit"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	if raw.Ret == 0 {
		return nil, fmt.Errorf("get users failed, ret=%d", raw.Ret)
	}
	users := make([]*UserInfo, 0, len(raw.Data))
	for _, d := range raw.Data {
		users = append(users, &UserInfo{
			ID: d.ID, Email: d.Email, UUID: d.UUID,
			Password: d.Passwd, Method: d.Method, SpeedLimit: d.SpeedLimit,
		})
	}
	return users, nil
}

func (c *SSPanelClient) ReportTraffic(reports []UserTraffic) error {
	type row struct {
		UserID int   `json:"user_id"`
		U      int64 `json:"u"`
		D      int64 `json:"d"`
	}
	rows := make([]row, 0, len(reports))
	for _, r := range reports {
		rows = append(rows, row{r.UserID, r.Upload, r.Download})
	}
	payload, _ := json.Marshal(map[string]any{"data": rows})
	_, err := c.doPost(c.withKey(fmt.Sprintf("/mod_mu/users/traffic?node_id=%d", c.nodeID)), "application/json", payload)
	return err
}

func (c *SSPanelClient) ReportAliveIP(reports []AliveIP) error {
	payload, _ := json.Marshal(map[string]any{"data": reports})
	_, err := c.doPost(c.withKey(fmt.Sprintf("/mod_mu/users/aliveip?node_id=%d", c.nodeID)), "application/json", payload)
	return err
}

func (c *SSPanelClient) ReportNodeInfo(status *NodeStatus) error {
	payload, _ := json.Marshal(status)
	_, err := c.doPost(c.withKey(fmt.Sprintf("/mod_mu/nodes/%d/info", c.nodeID)), "application/json", payload)
	return err
}
