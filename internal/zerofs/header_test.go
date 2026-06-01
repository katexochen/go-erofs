package zerofs

import (
	"errors"
	"testing"

	"github.com/erofs/go-erofs/internal/disk"
)

func TestParseHeaderRejectsUnsupported(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*[disk.SizeZMapHeader]byte)
	}{
		{"InlinePcluster", func(b *[disk.SizeZMapHeader]byte) {
			// advise bit 3 (ZAdviseInlinePcluster) at byte offset 4 low byte
			b[4] = disk.ZAdviseInlinePcluster
		}},
		{"FragmentPcluster", func(b *[disk.SizeZMapHeader]byte) {
			b[4] = disk.ZAdviseFragmentPcluster
		}},
		{"InterlacedPcluster", func(b *[disk.SizeZMapHeader]byte) {
			b[4] = disk.ZAdviseInterlacedPcluster
		}},
		{"IdataSizeWithInlinePcluster", func(b *[disk.SizeZMapHeader]byte) {
			// idata_size is only meaningful with INLINE_PCLUSTER advise;
			// the combination is what we still don't implement.
			b[2] = 0x10                          // IdataSize low byte
			b[4] = disk.ZAdviseInlinePcluster
		}},
		{"AlgoLZMA", func(b *[disk.SizeZMapHeader]byte) {
			b[6] = disk.AlgoIDLZMA // head1 algorithm = LZMA (deferred)
		}},
		{"AlgoHead2", func(b *[disk.SizeZMapHeader]byte) {
			b[6] = 0x10 // head2 algorithm = 1, head1 = 0
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b [disk.SizeZMapHeader]byte
			tc.mod(&b)
			_, err := ParseHeader(b[:])
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("expected ErrNotImplemented, got %v", err)
			}
		})
	}
}

func TestParseHeaderAcceptsZero(t *testing.T) {
	var b [disk.SizeZMapHeader]byte
	h, err := ParseHeader(b[:])
	if err != nil {
		t.Fatalf("zero header should be accepted, got %v", err)
	}
	if h.Advise != 0 || h.AlgorithmType != 0 {
		t.Fatalf("decoded zero header has non-zero fields: %+v", h)
	}
}

func TestParseHeaderAcceptsBigPcluster1(t *testing.T) {
	// BigPcluster1 is accepted (handled by FindPclusterForOffset).
	var b [disk.SizeZMapHeader]byte
	b[4] = disk.ZAdviseBigPcluster1
	h, err := ParseHeader(b[:])
	if err != nil {
		t.Fatalf("BigPcluster1 should be accepted, got %v", err)
	}
	if h.Advise&disk.ZAdviseBigPcluster1 == 0 {
		t.Fatalf("BigPcluster1 bit lost in decode")
	}
}

func TestParseHeaderAcceptsFragmentInode(t *testing.T) {
	// A fragment-inode header has h_clusterbits bit 7 set. The four bytes
	// that look like reserved1 + idata_size are actually h_fragmentoff and
	// can hold any value (especially a non-zero high half). The accepted
	// header should round-trip those bytes intact.
	var b [disk.SizeZMapHeader]byte
	// h_fragmentoff = 0x05eeb15f (low half = h_reserved1, high half = h_idata_size)
	b[0] = 0x5f
	b[1] = 0xb1
	b[2] = 0xee
	b[3] = 0x05
	b[7] = disk.ZClusterBitsFragmentInode

	h, err := ParseHeader(b[:])
	if err != nil {
		t.Fatalf("fragment-inode header should be accepted, got %v", err)
	}
	if h.ClusterBits&disk.ZClusterBitsFragmentInode == 0 {
		t.Fatalf("FRAGMENT_INODE bit lost in decode: cluster_bits=0x%02x", h.ClusterBits)
	}
	if got, want := uint32(h.Reserved1)|uint32(h.IdataSize)<<16, uint32(0x05eeb15f); got != want {
		t.Fatalf("h_fragmentoff: got 0x%08x, want 0x%08x", got, want)
	}
}

func TestParseHeaderShortBuffer(t *testing.T) {
	_, err := ParseHeader(make([]byte, 4))
	if err == nil {
		t.Fatal("expected error on short buffer, got nil")
	}
}
