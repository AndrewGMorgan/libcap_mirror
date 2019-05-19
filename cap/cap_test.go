package cap

import (
	"fmt"
	"testing"
)

func TestString(t *testing.T) {
	a := CHOWN
	if got, want := a.String(), "cap_chown"; got != want {
		t.Fatalf("pretty basic failure: got=%q, want=%q", got, want)
	}
}

func TestText(t *testing.T) {
	vs := []struct {
		from, to string
		err      error
	}{
		{"", "", ErrBadText},
		{"=", "=", nil},
		{"= cap_chown+iep cap_chown-i", "= cap_chown+ep", nil},
		{"= cap_setfcap,cap_chown+iep cap_chown-i", "= cap_setfcap+epi cap_chown+ep", nil},
	}
	for i, v := range vs {
		c, err := FromText(v.from)
		if err != v.err {
			t.Errorf("[%d] parsing %q failed: got=%v, want=%v", i, v.from, err, v.err)
			continue
		}
		if err != nil {
			continue
		}
		to := c.String()
		if to != v.to {
			t.Errorf("[%d] failed to stringify cap: %q -> got=%q, want=%q", i, v.from, to, v.to)
		}
		if d, err := FromText(to); err != nil {
			t.Errorf("[%d] failed to reparse %q: %v", i, to, err)
		} else if got := d.String(); got != to {
			t.Errorf("[%d] failed to stringify %q getting %q", i, to, got)
		}
	}
}

func same(a, b *Set) error {
	if (a == nil) != (b == nil) {
		return fmt.Errorf("nil-ness miscompare: %q vs %v", a, b)
	}
	if a == nil {
		return nil
	}
	if a.nsRoot != b.nsRoot {
		return fmt.Errorf("capabilities differ in nsRoot: a=%d b=%d", a.nsRoot, b.nsRoot)
	}
	for i, f := range a.flat {
		g := b.flat[i]
		for s := Effective; s <= Inheritable; s++ {
			if got, want := f[s], g[s]; got != want {
				return fmt.Errorf("capabilities differ: a[%d].flat[%v]=0x%08x b[%d].flat[%v]=0x%08x", i, s, got, i, s, want)
			}
		}
	}
	return nil
}

func TestImportExport(t *testing.T) {
	// Sanity check empty import/export.
	c := NewSet()
	if ex, err := c.Export(); err != nil {
		t.Fatalf("failed to export empty set: %v", err)
	} else if len(ex) != 5 {
		t.Fatalf("wrong length: got=%d want=%d", len(ex), 5)
	} else if im, err := Import(ex); err != nil {
		t.Fatalf("failed to import empty set: %v", err)
	} else if got, want := im.String(), c.String(); got != want {
		t.Fatalf("import != export: got=%q want=%q", got, want)
	}
	// Now keep flipping bits on and off and validate that all
	// forms of import/export work.
	for i := uint(0); i < 7000; i += 13 {
		s := Flag(i % 3)
		v := Value(i % (maxValues + 3))
		c.SetFlag(s, i&17 < 8, v)
		if ex, err := c.Export(); err != nil {
			t.Fatalf("[%d] failed to export empty set: %v", i, err)
		} else if im, err := Import(ex); err != nil {
			t.Fatalf("[%d] failed to import empty set: %v", i, err)
		} else if got, want := im.String(), c.String(); got != want {
			t.Fatalf("[%d] import != export: got=%q want=%q [%02x]", i, got, want, ex)
		} else if parsed, err := FromText(got); err != nil {
			t.Fatalf("[%d] failed to parse %q: %v", i, got, err)
		} else if err := same(c, parsed); err != nil {
			t.Fatalf("[%d] miscompare: %v", i, err)
		}
	}
}
