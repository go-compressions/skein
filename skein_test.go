package skein

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

func message(n int) []byte {
	m := make([]byte, n)
	for i := range m {
		m[i] = byte(i*31 + 7)
	}
	return m
}

func ramp(n int) []byte {
	k := make([]byte, n)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

// TestOpenZFSVectors checks every line of the vector file, produced by
// compiling OpenZFS zfs-2.3.0 module/icp/algs/skein verbatim (see README).
func TestOpenZFSVectors(t *testing.T) {
	f, err := os.Open("testdata/openzfs-2.3.0-vectors.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	count := map[string]int{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 3 {
			t.Fatalf("bad line %q", sc.Text())
		}
		n, err := strconv.Atoi(fs[1])
		if err != nil {
			t.Fatal(err)
		}
		want := fs[2]
		var d *Digest
		switch fs[0] {
		case "unkeyed256":
			d = New(256, nil)
		case "salted256":
			d = New(256, ramp(32))
		case "key17-512":
			d = New(512, ramp(17))
		case "unkeyed1000":
			d = New(1000, nil)
		default:
			t.Fatalf("unknown mode %q", fs[0])
		}
		d.Write(message(n))
		if got := hex.EncodeToString(d.Sum(nil)); got != want {
			t.Fatalf("%s len %d: got %s want %s", fs[0], n, got, want)
		}
		count[fs[0]]++
	}
	if len(count) != 4 {
		t.Fatalf("modes seen: %v", count)
	}
}

// The empty-message Skein-512-256 from the Skein reference / OpenZFS run.
func TestEmpty(t *testing.T) {
	got := hex.EncodeToString(New(256, nil).Sum(nil))
	if want := "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621"; got != want {
		t.Fatalf("got %s", got)
	}
}

func TestStreamingAndReset(t *testing.T) {
	m := message(1000)
	whole := New(256, ramp(32))
	whole.Write(m)
	want := whole.Sum(nil)
	for _, step := range []int{1, 3, 63, 64, 65, 200} {
		d := New(256, ramp(32))
		for i := 0; i < len(m); i += step {
			e := i + step
			if e > len(m) {
				e = len(m)
			}
			d.Write(m[i:e])
		}
		if !bytes.Equal(d.Sum(nil), want) {
			t.Fatalf("step %d differs", step)
		}
		// Sum must not disturb the state, Reset must restore it.
		if !bytes.Equal(d.Sum(nil), want) {
			t.Fatalf("step %d: Sum not idempotent", step)
		}
		d.Reset()
		d.Write(m)
		if !bytes.Equal(d.Sum(nil), want) {
			t.Fatalf("step %d: Reset differs", step)
		}
	}
	if whole.Size() != 32 || whole.BlockSize() != 64 {
		t.Fatal("size")
	}
	pre := []byte("pre")
	if got := whole.Sum(pre); !bytes.Equal(got[:3], pre) || !bytes.Equal(got[3:], want) {
		t.Fatal("Sum must append")
	}
}

func TestClone(t *testing.T) {
	tmpl := New(256, ramp(32)) // the ZFS context template
	a, b := tmpl.Clone(), tmpl.Clone()
	a.Write([]byte("a"))
	b.Write([]byte("b"))
	if bytes.Equal(a.Sum(nil), b.Sum(nil)) {
		t.Fatal("clones share state")
	}
	c := tmpl.Clone()
	c.Write([]byte("a"))
	if !bytes.Equal(c.Sum(nil), a.Sum(nil)) {
		t.Fatal("template was disturbed")
	}
}

// The unrolled block function must agree with the table-driven one.
func TestUnrolledMatchesLoop(t *testing.T) {
	m := message(64 * 5)
	a, b := New(256, ramp(32)), New(256, ramp(32))
	a.process(m, 5, 64)
	b.processLoop(m, 5, 64)
	if a.x != b.x || a.t != b.t {
		t.Fatal("process and processLoop differ")
	}
}

func TestBadLength(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	New(0, nil)
}

func BenchmarkSkein512_256_4K(b *testing.B) {
	m := message(4096)
	tmpl := New(256, ramp(32))
	b.SetBytes(4096)
	for i := 0; i < b.N; i++ {
		d := tmpl.Clone()
		d.Write(m)
		d.Sum(nil)
	}
}

func BenchmarkSkein512_256_128K(b *testing.B) {
	m := message(128 << 10)
	tmpl := New(256, ramp(32))
	b.SetBytes(int64(len(m)))
	for i := 0; i < b.N; i++ {
		d := tmpl.Clone()
		d.Write(m)
		d.Sum(nil)
	}
}
