package cap

import (
	"bufio"
	"errors"
	"strconv"
	"strings"
)

// String converts a capability Value into its canonical text
// representation.
func (v Value) String() string {
	name, ok := names[v]
	if ok {
		return name
	}
	// Un-named capabilities are referred to numerically (in decimal).
	return strconv.Itoa(int(v))
}

// FromName converts a named capability Value to its binary
// representation.
func FromName(name string) (Value, error) {
	startUp.Do(cInit)
	v, ok := bits[name]
	if ok {
		if v >= Value(words*32) {
			return 0, ErrBadValue
		}
		return v, nil
	}
	i, err := strconv.Atoi(name)
	if err != nil {
		return 0, err
	}
	if i >= 0 && i < int(words*32) {
		return Value(i), nil
	}
	return 0, ErrBadValue
}

const (
	eBin uint = (1 << Effective)
	pBin      = (1 << Permitted)
	iBin      = (1 << Inheritable)
)

var combos = []string{"", "e", "p", "ep", "i", "ei", "pi", "epi"}

// histo generates a histogram of flag state combinations.
func (c *Set) histo(m uint, bins []int, patterns []uint, from, limit Value) uint {
	for v := from; v < limit; v++ {
		b := uint(v & 31)
		u, mask, err := bitOf(0, v)
		if err != nil {
			break
		}
		x := uint((c.flat[u][Effective]&mask)>>b) * eBin
		x |= uint((c.flat[u][Permitted]&mask)>>b) * pBin
		x |= uint((c.flat[u][Inheritable]&mask)>>b) * iBin
		bins[x]++
		patterns[uint(v)] = x
		if bins[m] <= bins[x] {
			m = x
		}
	}
	return m
}

// String converts a full capability Set into it canonical readable
// string representation (which may contain spaces).
func (c *Set) String() string {
	if c == nil {
		return "<invalid>"
	}
	bins := make([]int, 8)
	patterns := make([]uint, 32*words)

	c.mu.RLock()
	defer c.mu.RUnlock()

	// Note, in order to have a *Set pointer, startUp.Do(cInit)
	// must have been called which sets maxValues.
	m := c.histo(0, bins, patterns, Value(maxValues), 32*Value(words))
	// Background state is the most popular of the unnamed bits,
	// this has the effect of tending to not list numerical values
	// for unnamed capabilities in the generated text.
	vs := []string{"=" + combos[m]}

	// Extend the histogram with the remaining Value occurrences.
	c.histo(m, bins, patterns, 0, Value(maxValues))
	for i := uint(8); i > 0; {
		i--
		if i == m || bins[i] == 0 {
			continue
		}
		var list []string
		for j, p := range patterns {
			if p != i {
				continue
			}
			list = append(list, Value(j).String())
		}
		if cf := i & ^m; cf != 0 {
			vs = append(vs, strings.Join(list, ",")+"+"+combos[cf])
		}
		if cf := m & ^i; cf != 0 {
			vs = append(vs, strings.Join(list, ",")+"-"+combos[cf])
		}
	}
	return strings.Join(vs, " ")
}

// ErrBadText is returned if the text for a capability set cannot be parsed.
var ErrBadText = errors.New("bad text")

// FromText converts the canonical text representation for a Set into
// a freshly allocated Set.
func FromText(text string) (*Set, error) {
	c := NewSet()
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Split(bufio.ScanWords)
	chunks := 0
	for scanner.Scan() {
		chunks++
		// Parsing for xxx[-+=][eip]+
		t := scanner.Text()
		i := strings.IndexAny(t, "=+-")
		if i < 0 {
			return nil, ErrBadText
		}
		var vs []Value
		sep := t[i]
		if vals := t[:i]; vals != "all" && vals != "" {
			for _, name := range strings.Split(vals, ",") {
				v, err := FromName(name)
				if err != nil {
					return nil, ErrBadText
				}
				vs = append(vs, v)
			}
		} else if sep != '=' && vals == "" {
			return nil, ErrBadText // Only "=" supports ""=="all".
		}
		sets := t[i+1:]
		var fE, fP, fI bool
		for j := 0; j < len(sets); j++ {
			switch sets[j] {
			case 'e':
				fE = true
			case 'p':
				fP = true
			case 'i':
				fI = true
			default:
				return nil, ErrBadText
			}
		}
		if sep == '=' {
			keep := len(vs) == 0 // '=' means default to off except setting individual values.
			c.forceFlag(Effective, fE && keep)
			c.forceFlag(Permitted, fP && keep)
			c.forceFlag(Inheritable, fI && keep)
			if keep {
				continue
			}
		}
		if fE {
			c.SetFlag(Effective, sep != '-', vs...)
		}
		if fP {
			c.SetFlag(Permitted, sep != '-', vs...)
		}
		if fI {
			c.SetFlag(Inheritable, sep == '+', vs...)
		}
	}
	if chunks == 0 {
		return nil, ErrBadText
	}
	return c, nil
}
