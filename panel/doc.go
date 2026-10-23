// Package panel is a RECONSTRUCTION of heki v1.2.8's heki/panel package,
// rebuilt from static analysis (IDA/Hex-Rays) of the shipped binary. It is
// behavior-equivalent Go, NOT the original source.
//
// panel is the central hub: it talks to a billing panel (SSPanel, Xboard/V2board,
// PPanel, Metron, or heki's own hekiv1) through a uniform PanelClient interface,
// and the Scheduler drives three loops — sync (pull users/config), report (push
// traffic/alive-IP) and heartbeat — while enforcing the license via injected
// hooks and a runtime guard.
//
//   types.go     - PanelClient interface, NodeInfo/UserInfo/traffic types.
//   scheduler.go - Scheduler: Start, syncLoop/doSync, reportLoop/doReport,
//                  heartbeatLoop/doHeartbeat, mustPassRuntimeGuard, license hooks.
//   sspanel.go   - SSPanel (mod_mu) client.
//   xboard.go    - Xboard/V2board (UniProxy) client with node_type probing.
//   ppanel.go    - PPanel (/api/v2) client.
//   metron.go    - Metron client.
//   hekiv1.go    - heki's own panel client (ETag conditional GET).
//   resolve.go   - panel-type detection and client construction.
//
// Faithful (observed): the API endpoints (/mod_mu/*, /api/v1/server/UniProxy,
// /api/v2/server), the doSync order (refresh-license -> dedup -> GetNodeInfo +
// GetUsers -> cap by license max users), ETag conditional requests, and the
// runtime-guard gating (mustPassRuntimeGuard -> log.Fatalf on failure).
//
// Reconstructed / scoped: identifier and field order; per-protocol config
// parsers are endpoint-accurate skeletons (the full field mapping lives across
// the config package); HTTP bodies follow the documented panel formats.
//
// Built and vet-checked with go1.26.3. Still a reconstruction, not the original.
package panel
