package modbus

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Letters are the canonical form; the numeric form stays parseable for configurations
// written against the earlier uint field.
func TestParity_UnmarshalLetters(t *testing.T) {
	cases := map[string]Parity{
		`"N"`:    ParityNone,
		`"n"`:    ParityNone,
		`"none"`: ParityNone,
		`"NONE"`: ParityNone,
		`"E"`:    ParityEven,
		`"even"`: ParityEven,
		`"O"`:    ParityOdd,
		`"odd"`:  ParityOdd,
		`" e "`:  ParityEven, // field configs carry stray whitespace
		`""`:     ParityNone, // empty means default
	}
	for in, want := range cases {
		var p Parity
		assert.Nil(t, json.Unmarshal([]byte(in), &p), in)
		assert.Equal(t, want, p, in)
	}
}

func TestParity_UnmarshalNumbers(t *testing.T) {
	cases := map[string]Parity{
		`0`:   ParityNone,
		`1`:   ParityEven,
		`2`:   ParityOdd,
		`"0"`: ParityNone, // numbers arriving as strings from form input
		`"1"`: ParityEven,
		`"2"`: ParityOdd,
	}
	for in, want := range cases {
		var p Parity
		assert.Nil(t, json.Unmarshal([]byte(in), &p), in)
		assert.Equal(t, want, p, in)
	}
}

// Mark and Space must fail loudly: the driver has no such mode, and defaulting to
// no-parity would leave a link that looks configured but garbles every frame.
func TestParity_MarkSpaceRejectedWithReason(t *testing.T) {
	for _, in := range []string{`"M"`, `"mark"`, `"S"`, `"space"`} {
		var p Parity
		err := json.Unmarshal([]byte(in), &p)
		assert.NotNil(t, err, in)
		assert.Contains(t, err.Error(), "not supported", in)
		// The message should point at the component that does support it.
		assert.Contains(t, err.Error(), "x/serial", in)
	}
}

func TestParity_InvalidRejected(t *testing.T) {
	for _, in := range []string{`"bogus"`, `3`, `-1`, `true`, `[]`} {
		var p Parity
		assert.NotNil(t, json.Unmarshal([]byte(in), &p), in)
	}
}

// Marshalling always emits the letter, so exported configs carry one representation
// no matter which form was supplied.
func TestParity_MarshalAlwaysLetter(t *testing.T) {
	for p, want := range map[Parity]string{ParityNone: `"N"`, ParityEven: `"E"`, ParityOdd: `"O"`} {
		b, err := json.Marshal(p)
		assert.Nil(t, err)
		assert.Equal(t, want, string(b))
	}
	// Out-of-range values are an error rather than a silently wrong letter.
	_, err := json.Marshal(Parity(9))
	assert.NotNil(t, err)
}

// A numeric input round-trips into the letter form: this is what normalises old configs.
func TestParity_NumericInputMarshalsAsLetter(t *testing.T) {
	var p Parity
	assert.Nil(t, json.Unmarshal([]byte(`1`), &p))
	b, err := json.Marshal(p)
	assert.Nil(t, err)
	assert.Equal(t, `"E"`, string(b), "numeric 1 must normalise to the even letter")
}

// The internal value must keep matching the underlying library constants, otherwise
// every use site would need a lookup and odd/even could drift apart.
func TestParity_MatchesLibraryConstants(t *testing.T) {
	assert.Equal(t, uint(0), uint(ParityNone))
	assert.Equal(t, uint(1), uint(ParityEven))
	assert.Equal(t, uint(2), uint(ParityOdd))
}

// x/serial lists None/Odd/Even while this driver lists None/Even/Odd. Anything mapping
// by position swaps odd and even, so pin the letters to their numbers explicitly.
func TestParity_OddEvenNotSwapped(t *testing.T) {
	var even, odd Parity
	assert.Nil(t, json.Unmarshal([]byte(`"E"`), &even))
	assert.Nil(t, json.Unmarshal([]byte(`"O"`), &odd))
	assert.Equal(t, uint(1), uint(even), `"E" must be 1 (PARITY_EVEN)`)
	assert.Equal(t, uint(2), uint(odd), `"O" must be 2 (PARITY_ODD)`)
	assert.NotEqual(t, even, odd)
}

func TestParseParity_Exported(t *testing.T) {
	p, err := ParseParity("even")
	assert.Nil(t, err)
	assert.Equal(t, ParityEven, p)

	_, err = ParseParity("mark")
	assert.NotNil(t, err)

	_, err = ParseParity("nope")
	assert.NotNil(t, err)
}

func TestParity_String(t *testing.T) {
	assert.Equal(t, "N", ParityNone.String())
	assert.Equal(t, "E", ParityEven.String())
	assert.Equal(t, "O", ParityOdd.String())
	assert.Equal(t, "?", Parity(9).String())
}

// RtuConfig as a whole must accept both forms, since that is what real configs contain.
func TestRtuConfig_AcceptsBothParityForms(t *testing.T) {
	var withLetter, withNumber RtuConfig
	assert.Nil(t, json.Unmarshal([]byte(`{"speed":19200,"dataBits":8,"parity":"E","stopBits":1}`), &withLetter))
	assert.Nil(t, json.Unmarshal([]byte(`{"speed":19200,"dataBits":8,"parity":1,"stopBits":1}`), &withNumber))
	assert.Equal(t, ParityEven, withLetter.Parity)
	assert.Equal(t, withLetter, withNumber, "both forms must yield the same config")
}
