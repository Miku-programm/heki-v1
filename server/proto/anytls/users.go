package anytls

import (
	"fmt"
	"strings"
	"sync"
)

// UserInfo is a configured AnyTLS account. AnyTLS authenticates by a per-user
// "tag" (password/identity) presented in the handshake. Mirrors heki/types.UserInfo.
type UserInfo struct {
	Email    string
	Tag      string // primary auth identity
	SpeedBps int64
}

// userTagWithSuffix builds a tagged identity. A zero suffix returns the bare
// tag; a positive suffix yields "tag#N" (used to disambiguate duplicate tags).
// Mirrors userTagWithSuffix.
func userTagWithSuffix(tag string, suffix int) string {
	tag = strings.TrimSpace(tag)
	if suffix <= 0 {
		return tag
	}
	return fmt.Sprintf("%s#%d", tag, suffix)
}

// authIdentitiesForUser returns every identity string a user may present
// (its tag plus suffixed variants when the tag collides). Mirrors
// (*Handler).authIdentitiesForUser / appendAnyTLSAuthIdentity.
func authIdentitiesForUser(u *UserInfo, suffix int) []string {
	ids := []string{userTagWithSuffix(u.Tag, 0)}
	if suffix > 0 {
		ids = append(ids, userTagWithSuffix(u.Tag, suffix))
	}
	return ids
}

// userTable maps auth identity -> user, built from the configured users.
type userTable struct {
	mu    sync.RWMutex
	byTag map[string]*UserInfo
}

func newUserTable() *userTable {
	return &userTable{byTag: map[string]*UserInfo{}}
}

// build constructs the tag->user map, assigning #N suffixes to colliding tags
// (buildTaggedUserMap).
func buildTaggedUserMap(users []*UserInfo) map[string]*UserInfo {
	out := make(map[string]*UserInfo, len(users))
	seen := map[string]int{}
	for _, u := range users {
		base := strings.TrimSpace(u.Tag)
		n := seen[base]
		seen[base] = n + 1
		for _, id := range authIdentitiesForUser(u, n) {
			out[id] = u
		}
	}
	return out
}

// UpdateUsers replaces the user set.
func (t *userTable) UpdateUsers(users []*UserInfo) {
	m := buildTaggedUserMap(users)
	t.mu.Lock()
	t.byTag = m
	t.mu.Unlock()
}

// UpdateUsersWithGrace swaps in a new user set but keeps removed users'
// identities valid for the grace window, so in-flight sessions are not cut.
// Mirrors UpdateUsersWithGrace.
func (t *userTable) UpdateUsersWithGrace(users []*UserInfo) {
	m := buildTaggedUserMap(users)
	t.mu.Lock()
	for id, u := range t.byTag {
		if _, ok := m[id]; !ok {
			m[id] = u // retain during grace
		}
	}
	t.byTag = m
	t.mu.Unlock()
}

// findUserByTag looks up a user by presented auth identity (findUserByTag).
func (t *userTable) findUserByTag(tag string) *UserInfo {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.byTag[strings.TrimSpace(tag)]
}
