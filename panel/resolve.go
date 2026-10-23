package panel

import (
	"fmt"
	"strings"
)

// PanelType identifies a billing panel implementation.
type PanelType string

const (
	PanelSSPanel PanelType = "sspanel"
	PanelXBoard  PanelType = "xboard" // also v2board / xiaov2board
	PanelPPanel  PanelType = "ppanel"
	PanelMetron  PanelType = "metron"
	PanelHekiV1  PanelType = "hekiv1"
)

// NormalizePanelType maps the many aliases onto the canonical PanelType.
func NormalizePanelType(s string) PanelType {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "sspanel", "mod_mu", "sspanel-uim":
		return PanelSSPanel
	case "xboard", "v2board", "xiaov2board", "uniproxy":
		return PanelXBoard
	case "ppanel":
		return PanelPPanel
	case "metron":
		return PanelMetron
	case "hekiv1", "heki":
		return PanelHekiV1
	default:
		return PanelXBoard // the binary's default probe target
	}
}

// NewClient constructs the PanelClient for a panel type.
func NewClient(panelType, baseURL, key string, nodeID int) (PanelClient, error) {
	switch NormalizePanelType(panelType) {
	case PanelSSPanel:
		return NewSSPanelClient(baseURL, key, nodeID), nil
	case PanelXBoard:
		return NewXBoardClient(baseURL, key, nodeID), nil
	case PanelPPanel:
		return NewPPanelClient(baseURL, key, nodeID), nil
	case PanelMetron:
		return NewMetronClient(baseURL, key, nodeID), nil
	case PanelHekiV1:
		return NewHekiV1Client(baseURL, key, nodeID), nil
	default:
		return nil, fmt.Errorf("panel: unknown panel type %q", panelType)
	}
}

// Ensure every client satisfies PanelClient at compile time.
var (
	_ PanelClient = (*SSPanelClient)(nil)
	_ PanelClient = (*XBoardClient)(nil)
	_ PanelClient = (*PPanelClient)(nil)
	_ PanelClient = (*MetronClient)(nil)
	_ PanelClient = (*HekiV1Client)(nil)
)
