package panel

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// XBoardClient talks to Xboard/V2board's UniProxy API:
//
//	GET  /api/v1/server/UniProxy/config?node_id=&node_type=&token=
//	GET  /api/v1/server/UniProxy/user?node_id=&node_type=&token=
//	POST /api/v1/server/UniProxy/push   (traffic)
//	POST /api/v1/server/UniProxy/alive  (alive ip)
//
// node_type is probed among candidates (vmess/vless/trojan/shadowsocks/...).
type XBoardClient struct {
	httpBase
	nodeID   int
	nodeType string // cached once probed
}

func NewXBoardClient(baseURL, token string, nodeID int) *XBoardClient {
	return &XBoardClient{httpBase: newHTTPBase(strings.TrimRight(baseURL, "/"), token), nodeID: nodeID}
}

func (c *XBoardClient) GetNodeID() int { return c.nodeID }

func (c *XBoardClient) getAPINodeType() string { return c.nodeType }
func (c *XBoardClient) setAPINodeType(t string) { c.nodeType = t }

// dataNodeTypeCandidates lists the node_type values to probe.
func (c *XBoardClient) dataNodeTypeCandidates() []string {
	return []string{"vmess", "vless", "trojan", "shadowsocks", "hysteria", "tuic", "anytls"}
}

func (c *XBoardClient) buildURL(path, nodeType string) string {
	q := url.Values{}
	q.Set("node_id", fmt.Sprintf("%d", c.nodeID))
	if nodeType != "" {
		q.Set("node_type", nodeType)
	}
	q.Set("token", c.key)
	return c.httpBase.buildURL("/api/v1/server/UniProxy"+path) + "?" + q.Encode()
}

// doGetNodeConfigRaw probes node_type candidates until one returns config.
func (c *XBoardClient) doGetNodeConfigRaw() ([]byte, string, error) {
	cands := c.dataNodeTypeCandidates()
	if c.nodeType != "" {
		cands = append([]string{c.nodeType}, cands...)
	}
	var lastErr error
	for _, nt := range cands {
		body, etag, nm, err := c.doGet(c.buildURL("/config", nt))
		if err != nil {
			lastErr = err
			continue
		}
		if nm {
			return nil, nt, nil
		}
		c.etag = etag
		c.setAPINodeType(nt)
		return body, nt, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("get node config: no node_type matched")
	}
	return nil, "", lastErr
}

func (c *XBoardClient) GetNodeInfo() (*NodeInfo, error) {
	body, nt, err := c.doGetNodeConfigRaw()
	if err != nil {
		return nil, err
	}
	ni := &NodeInfo{NodeID: c.nodeID, ETag: c.etag, Raw: body}
	c.applyCommonNodeConfig(ni, nt, body)
	return ni, nil
}

// applyCommonNodeConfig maps the common fields; per-protocol parsers
// (parseVMessConfig, parseVLESSConfig, ...) fill Protocols from nt+body.
func (c *XBoardClient) applyCommonNodeConfig(ni *NodeInfo, nodeType string, body []byte) {
	var common struct {
		ServerPort int `json:"server_port"`
		SpeedLimit int `json:"speed_limit"`
	}
	_ = json.Unmarshal(body, &common)
	ni.SpeedLimit = common.SpeedLimit
	ni.Protocols = []ProtocolConfig{{Type: nodeType, Port: common.ServerPort}}
}

// resolveXBoardSS2022Password handles the SS-2022 server key/password quirk.
func (c *XBoardClient) resolveXBoardSS2022Password(serverKey, userKey string) string {
	if serverKey == "" {
		return userKey
	}
	return serverKey + ":" + userKey
}

func (c *XBoardClient) GetUsers() ([]*UserInfo, error) {
	body, _, nm, err := c.doGet(c.buildURL("/user", c.getAPINodeType()))
	if err != nil {
		return nil, err
	}
	if nm {
		return nil, fmt.Errorf("get users: empty response (304?)")
	}
	var raw struct {
		Users []struct {
			ID         int    `json:"id"`
			UUID       string `json:"uuid"`
			Email      string `json:"email"`
			SpeedLimit int    `json:"speed_limit"`
		} `json:"users"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse users: %w", err)
	}
	out := make([]*UserInfo, 0, len(raw.Users))
	for _, u := range raw.Users {
		out = append(out, &UserInfo{ID: u.ID, UUID: u.UUID, Email: u.Email, SpeedLimit: u.SpeedLimit})
	}
	return out, nil
}

func (c *XBoardClient) ReportTraffic(reports []UserTraffic) error {
	data := map[string][2]int64{}
	for _, r := range reports {
		data[fmt.Sprintf("%d", r.UserID)] = [2]int64{r.Upload, r.Download}
	}
	payload, _ := json.Marshal(data)
	_, err := c.doPost(c.buildURL("/push", c.getAPINodeType()), "application/json", payload)
	return err
}

func (c *XBoardClient) ReportAliveIP(reports []AliveIP) error {
	payload, _ := json.Marshal(reports)
	_, err := c.doPost(c.buildURL("/alive", c.getAPINodeType()), "application/json", payload)
	return err
}

func (c *XBoardClient) ReportNodeInfo(status *NodeStatus) error {
	payload, _ := json.Marshal(status)
	_, err := c.doPost(c.buildURL("/status", c.getAPINodeType()), "application/json", payload)
	return err
}
