package zerofs

import (
	"fmt"
	"io"
	"sync"

	"github.com/klauspost/compress/zstd"

	"github.com/erofs/go-erofs/internal/disk"
)

// Decompress reads the pcluster's compressed bytes via meta (which is the
// io.ReaderAt providing the same physical address space the lcluster
// BlkAddr values point into) and writes its decompressed output into out.
//
// out must be at least p.LogLen bytes long. The function returns the number
// of decompressed bytes written; for well-formed images this always equals
// p.LogLen.
func (d *Decoder) Decompress(p Pcluster, out []byte) (int, error) {
	blkSize := int(1) << d.BlkSizeBits
	if int64(len(out)) < p.LogLen {
		return 0, fmt.Errorf("decompress output buffer too small: %d < %d", len(out), p.LogLen)
	}
	physOff := int64(p.HeadBlk) << d.BlkSizeBits

	if p.HeadType == disk.ZLclusterTypePlain {
		n, err := readFull(d.Meta, out[:p.LogLen], physOff)
		if err != nil {
			return 0, fmt.Errorf("plain pcluster head=%d read: %w", p.HeadLcn, err)
		}
		return n, nil
	}
	if p.HeadType != disk.ZLclusterTypeHead1 {
		return 0, fmt.Errorf("unsupported head type %d: %w", p.HeadType, ErrNotImplemented)
	}

	src := make([]byte, int(p.NPhysBlks)*blkSize)
	if _, err := readFull(d.Meta, src, physOff); err != nil {
		return 0, fmt.Errorf("compressed pcluster head=%d read: %w", p.HeadLcn, err)
	}
	// Both LZ4_0Padding and EROFS Zstd place the compressed stream at the
	// END of the physical block(s) with leading zero padding, matching the
	// kernel's z_erofs_fixup_insize scan.
	inputMargin := 0
	for inputMargin < len(src) && src[inputMargin] == 0 {
		inputMargin++
	}
	if inputMargin >= len(src) {
		return 0, fmt.Errorf("compressed pcluster head=%d: physical block is all zeros: %w",
			p.HeadLcn, ErrCorrupt)
	}
	stream := src[inputMargin:]

	algo := d.Header.AlgorithmType & 0xF
	switch algo {
	case disk.AlgoIDLZ4:
		n, err := uncompressLZ4Partial(out[:p.LogLen], stream)
		if err != nil {
			return 0, fmt.Errorf("lz4 decompress head=%d (src=%d margin=%d, dst=%d): %w",
				p.HeadLcn, len(src), inputMargin, p.LogLen, err)
		}
		if int64(n) != p.LogLen {
			return 0, fmt.Errorf("lz4 decompress head=%d: got %d bytes, want %d: %w",
				p.HeadLcn, n, p.LogLen, ErrCorrupt)
		}
		return n, nil
	case disk.AlgoIDZstd:
		decoded, err := zstdDecode(stream, p.LogLen)
		if err != nil {
			return 0, fmt.Errorf("zstd decompress head=%d (src=%d margin=%d, dst=%d): %w",
				p.HeadLcn, len(src), inputMargin, p.LogLen, err)
		}
		if int64(len(decoded)) != p.LogLen {
			return 0, fmt.Errorf("zstd decompress head=%d: got %d bytes, want %d: %w",
				p.HeadLcn, len(decoded), p.LogLen, ErrCorrupt)
		}
		copy(out[:p.LogLen], decoded)
		return len(decoded), nil
	default:
		return 0, fmt.Errorf("unsupported compression algorithm %d: %w", algo, ErrNotImplemented)
	}
}

// zstdDecoder is shared across decompressions to avoid the substantial
// per-decoder setup cost of klauspost/compress/zstd. The library is safe for
// concurrent calls to DecodeAll.
var (
	zstdDec     *zstd.Decoder
	zstdDecOnce sync.Once
	zstdDecErr  error
)

func zstdDecode(src []byte, maxLen int64) ([]byte, error) {
	zstdDecOnce.Do(func() {
		// nil reader: DecodeAll is supported (and concurrent-safe) on a
		// decoder created without an input stream.
		zstdDec, zstdDecErr = zstd.NewReader(nil)
	})
	if zstdDecErr != nil {
		return nil, zstdDecErr
	}
	// Pre-allocate dst to maxLen to keep DecodeAll from growing the slice.
	dst := make([]byte, 0, maxLen)
	return zstdDec.DecodeAll(src, dst)
}

func readFull(r io.ReaderAt, dst []byte, off int64) (int, error) {
	total := 0
	for total < len(dst) {
		n, err := r.ReadAt(dst[total:], off+int64(total))
		total += n
		if err != nil {
			if total == len(dst) {
				return total, nil
			}
			return total, err
		}
	}
	return total, nil
}
