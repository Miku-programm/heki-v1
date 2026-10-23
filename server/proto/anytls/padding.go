package anytls

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
)

// DefaultPaddingScheme is the scheme recovered verbatim from the binary. Each
// "N=rules" line gives the record-size rules for the Nth packet of a session;
// "stop=K" means packets after index K use no padding.
const DefaultPaddingScheme = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000`

// checkSentinel is the size value emitted for the "c" token: "if there is still
// buffered application data, skip the remaining padding records for this packet".
const checkSentinel = -1

// PaddingScheme parses an AnyTLS padding scheme and generates per-packet record
// payload sizes. Mirrors the padding.PaddingFactory the binary wraps.
type PaddingScheme struct {
	stop  int
	rules map[int]string
}

// ParsePaddingScheme parses "key=value" lines into a PaddingScheme.
// Mirrors heki/config.normalizeAnyTLSPaddingSchemeRaw + validate.
func ParsePaddingScheme(raw string) (*PaddingScheme, error) {
	s := &PaddingScheme{stop: 0, rules: map[int]string{}}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("anytls: bad padding line %q", line)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k == "stop" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("anytls: bad stop %q", v)
			}
			s.stop = n
			continue
		}
		idx, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("anytls: bad packet index %q", k)
		}
		if err := validateRule(v); err != nil {
			return nil, err
		}
		s.rules[idx] = v
	}
	return s, nil
}

func validateRule(rule string) error {
	for _, tok := range strings.Split(rule, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "c" || tok == "" {
			continue
		}
		lo, hi, ok := strings.Cut(tok, "-")
		if !ok {
			return fmt.Errorf("anytls: bad padding token %q", tok)
		}
		if _, err := strconv.Atoi(strings.TrimSpace(lo)); err != nil {
			return err
		}
		if _, err := strconv.Atoi(strings.TrimSpace(hi)); err != nil {
			return err
		}
	}
	return nil
}

// Stop returns the packet index after which padding stops.
func (s *PaddingScheme) Stop() int { return s.stop }

// GenerateRecordPayloadSizes returns the record payload sizes for the given
// packet index. A size of checkSentinel (-1) means "stop here if more app data
// is pending". Range tokens draw a cryptographically-random size in [min,max].
// Mirrors padding.(*PaddingFactory).GenerateRecordPayloadSizes.
func (s *PaddingScheme) GenerateRecordPayloadSizes(pkt int) []int {
	rule, ok := s.rules[pkt]
	if !ok {
		return nil
	}
	var sizes []int
	for _, tok := range strings.Split(rule, ",") {
		tok = strings.TrimSpace(tok)
		switch {
		case tok == "c":
			sizes = append(sizes, checkSentinel)
		case tok == "":
			continue
		default:
			lo, hi, _ := strings.Cut(tok, "-")
			min, _ := strconv.Atoi(strings.TrimSpace(lo))
			max, _ := strconv.Atoi(strings.TrimSpace(hi))
			if max < min {
				min, max = max, min
			}
			if max == min {
				sizes = append(sizes, min)
			} else {
				sizes = append(sizes, min+cryptoRandInt(max-min))
			}
		}
	}
	return sizes
}

// cryptoRandInt returns a uniform random int in [0, n) using crypto/rand.Int,
// matching the binary's use of crypto/rand.Int for padding sizing.
func cryptoRandInt(n int) int {
	if n <= 0 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(v.Int64())
}

// SchemeKeys returns the packet indices in ascending order (mirrors
// sortAnyTLSPaddingSchemeKeys).
func (s *PaddingScheme) SchemeKeys() []int {
	keys := make([]int, 0, len(s.rules))
	for k := range s.rules {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}
