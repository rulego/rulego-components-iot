package modbus

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/mitchellh/mapstructure"
	"github.com/simonvetter/modbus"
)

// Parity is the serial parity mode for RTU links.
//
// Wire form is the letter used across the industry (N/O/E/M/S, as in "8E1"), matching
// what x/serial already accepts. Numeric form (0/1/2) is still parsed so configurations
// written against the earlier uint field keep working.
//
// The internal value stays aligned with simonvetter/modbus PARITY_* constants, so use
// sites just cast to uint with no lookup.
//
// Letters rather than numbers as the canonical form for three reasons:
//   - self-describing: "E" reads as even, 1 does not;
//   - x/serial's list is None/Odd/Even while this library's is None/Even/Odd — any
//     position-based mapping silently swaps odd and even, and a wrong parity shows up
//     as intermittent CRC errors, which is harder to diagnose than a link that never works;
//   - field notes and device manuals write 8N1 / 8E1.
type Parity uint

const (
	ParityNone Parity = Parity(modbus.PARITY_NONE) // N
	ParityEven Parity = Parity(modbus.PARITY_EVEN) // E
	ParityOdd  Parity = Parity(modbus.PARITY_ODD)  // O
)

// parityLetters maps the canonical letter of each supported mode.
var parityLetters = map[Parity]string{
	ParityNone: "N",
	ParityEven: "E",
	ParityOdd:  "O",
}

// String returns the canonical letter, or "?" for an out-of-range value.
func (p Parity) String() string {
	if s, ok := parityLetters[p]; ok {
		return s
	}
	return "?"
}

// MarshalJSON writes the letter, so exported configs and API responses carry one
// representation regardless of how the value was originally supplied.
func (p Parity) MarshalJSON() ([]byte, error) {
	if _, ok := parityLetters[p]; !ok {
		return nil, fmt.Errorf("modbus: invalid parity value %d", uint(p))
	}
	return json.Marshal(p.String())
}

// UnmarshalJSON accepts the letter (N/O/E, case-insensitive), the full word
// (none/odd/even), or the legacy number (0/1/2).
//
// Mark and Space are recognised only to reject them with a clear reason: the underlying
// library has no such constants, so silently falling back to no-parity would produce a
// link that appears configured yet garbles frames.
func (p *Parity) UnmarshalJSON(b []byte) error {
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		parsed, err := ParseParity(v)
		if err != nil {
			return err
		}
		*p = parsed
		return nil
	case float64:
		return p.fromNumber(int64(v))
	case nil:
		*p = ParityNone
		return nil
	}
	return fmt.Errorf("modbus: parity must be a string (N/O/E) or number (0/1/2), got %s", string(b))
}

// fromNumber accepts the legacy uint form.
func (p *Parity) fromNumber(n int64) error {
	switch Parity(n) {
	case ParityNone, ParityEven, ParityOdd:
		*p = Parity(n)
		return nil
	}
	return fmt.Errorf("modbus: parity %d out of range, want 0=None 1=Even 2=Odd (or \"N\"/\"E\"/\"O\")", n)
}

// ParseParity converts a textual parity into a Parity. Exported so callers holding
// loose configuration (maps, form input) can normalise without going through JSON.
func ParseParity(s string) (Parity, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", "N", "NONE":
		return ParityNone, nil
	case "E", "EVEN":
		return ParityEven, nil
	case "O", "ODD":
		return ParityOdd, nil
	case "M", "MARK", "S", "SPACE":
		return ParityNone, fmt.Errorf("modbus: parity %q not supported by the modbus rtu driver (only N/E/O); "+
			"mark/space parity is available on the raw x/serial component", strings.TrimSpace(s))
	}
	// Numbers may arrive as strings from form input or environment variables.
	if n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 32); err == nil {
		var p Parity
		if err := p.fromNumber(n); err != nil {
			return ParityNone, err
		}
		return p, nil
	}
	return ParityNone, fmt.Errorf("modbus: unknown parity %q, want N/E/O (or 0/1/2)", s)
}

// decodeConfig decodes node configuration exactly like maps.Map2Struct, plus letter
// parity. The stock mapstructure decoder only parses numbers into uint-kind fields and
// never calls UnmarshalJSON, so the letter form written by MarshalJSON (and submitted
// verbatim by the editor form) would fail Init with
// "cannot parse 'rtuConfig.parity' as uint: ... parsing \"N\"". The DecoderConfig must
// stay in sync with maps.Map2Struct or the two paths decode differently.
func decodeConfig(input any, out any) error {
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.ComposeDecodeHookFunc(
			mapstructure.StringToTimeDurationHookFunc(),
			parityHookFunc(),
		),
		WeaklyTypedInput: true,
		ZeroFields:       true,
		TagName:          "json",
		Result:           out,
	})
	if err != nil {
		return err
	}
	return decoder.Decode(input)
}

// parityHookFunc routes string input targeted at Parity through ParseParity;
// every other type combination passes through untouched.
func parityHookFunc() mapstructure.DecodeHookFunc {
	parityType := reflect.TypeOf(Parity(0))
	return func(from reflect.Type, to reflect.Type, data any) (any, error) {
		if to != parityType || from.Kind() != reflect.String {
			return data, nil
		}
		return ParseParity(data.(string))
	}
}
