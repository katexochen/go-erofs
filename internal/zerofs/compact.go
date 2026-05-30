package zerofs

import (
	"encoding/binary"
	"fmt"

	"github.com/erofs/go-erofs/internal/disk"
)

// decodeCompact reads the compact-format lcluster index entry at logical
// cluster index lcn. It supports both the compact-4B (vcnt=2) and
// compact-2B (vcnt=16) packings that mkfs.erofs emits, in the layout-
// dependent ordering [compact-4B prefix | compact-2B middle | compact-4B
// suffix] described by erofs-utils' z_erofs_convert_to_compacted_format.
//
// This is a direct port of erofs-utils' z_erofs_load_compact_lcluster
// (lib/zmap.c). Big-pcluster compact is not supported in this PR — a
// CBLKCNT marker triggers a clear error.
func (d *Decoder) decodeCompact(lcn int) (LclusterEntry, error) {
	if d.LclusterBits > 14 {
		return LclusterEntry{}, fmt.Errorf("compact format requires lclusterbits <= 14, got %d: %w",
			d.LclusterBits, ErrNotImplemented)
	}
	bigPcluster := d.Header.Advise&disk.ZAdviseBigPcluster1 != 0

	ebase := d.IndexBase
	totalidx := d.NLclusters

	// Layout regions:
	//   compacted_4b_initial: number of entries packed in 4-bytes-per-entry
	//     prefix used to align the compact-2B region to 32-byte groups.
	//   compacted_2b: number of entries packed in 2-bytes-per-entry middle.
	//   remainder: any trailing entries packed in 4-bytes-per-entry suffix.
	compacted4bInitial := int((32 - (ebase&31))/4) & 7
	compacted2b := 0
	if d.Header.Advise&disk.ZAdviseCompacted2B != 0 && compacted4bInitial < totalidx {
		compacted2b = (totalidx - compacted4bInitial) &^ 15 // rounddown(..., 16)
	}

	// Locate (group base, position within group) for our target lcn.
	pos := ebase
	amortizedshift := 2 // compact-4B
	lcRel := lcn
	if lcRel >= compacted4bInitial {
		pos += int64(compacted4bInitial) * 4
		lcRel -= compacted4bInitial
		if lcRel < compacted2b {
			amortizedshift = 1 // compact-2B
		} else {
			pos += int64(compacted2b) * 2
			lcRel -= compacted2b
		}
	}
	pos += int64(lcRel) << amortizedshift

	var vcnt int
	if amortizedshift == 2 && d.LclusterBits <= 14 {
		vcnt = 2
	} else if amortizedshift == 1 && d.LclusterBits <= 12 {
		vcnt = 16
	} else {
		return LclusterEntry{}, fmt.Errorf("unsupported compact configuration shift=%d lcbits=%d: %w",
			amortizedshift, d.LclusterBits, ErrNotImplemented)
	}

	groupSize := int64(vcnt) << amortizedshift
	groupBase := pos &^ (groupSize - 1)
	idxInGroup := int((pos - groupBase) >> amortizedshift)

	// Pull the full group (32 bytes for compact-2B, 8 for compact-4B).
	groupBuf := make([]byte, groupSize)
	if _, err := d.Meta.ReadAt(groupBuf, groupBase); err != nil {
		return LclusterEntry{}, fmt.Errorf("read compact group at %d: %w", groupBase, err)
	}

	lobits := int(d.LclusterBits)
	if lobits < 12 {
		lobits = 12
	}
	encodebits := ((vcnt << amortizedshift) - 4) * 8 / vcnt

	lo, typ := decodeCompactedBits(uint(lobits), groupBuf, encodebits*idxInGroup)
	e := LclusterEntry{Type: typ}

	if typ == disk.ZLclusterTypeNonhead {
		if lo&disk.ZLclusterD0CBlkCnt != 0 {
			if !bigPcluster {
				return LclusterEntry{}, fmt.Errorf("CBLKCNT marker without big_pcluster (compact): %w",
					ErrCorrupt)
			}
			e.CBlkCnt = uint16(lo &^ disk.ZLclusterD0CBlkCnt)
			e.DeltaPrev = 1
			return e, nil
		}
		if idxInGroup+1 != vcnt {
			// Normal NONHEAD: lo is delta[0] (backward distance to head).
			e.DeltaPrev = uint16(lo)
		} else {
			// Last-in-group NONHEAD: lo is delta[1] (forward distance).
			// Recover delta[0] from the previous entry: kernel logic is
			//   delta[0] = (previous entry's lo, or 0 if previous is HEAD/PLAIN,
			//              or 1 if previous is big-pcluster NONHEAD) + 1.
			prevLo, prevType := decodeCompactedBits(uint(lobits), groupBuf, encodebits*(idxInGroup-1))
			switch {
			case prevType != disk.ZLclusterTypeNonhead:
				e.DeltaPrev = 1
			case prevLo&disk.ZLclusterD0CBlkCnt != 0:
				e.DeltaPrev = 2 // 1 + 1
			default:
				e.DeltaPrev = uint16(prevLo) + 1
			}
			e.DeltaNext = uint16(lo)
		}
		return e, nil
	}

	// HEAD/PLAIN: lo is clusterofs, pblk derived from group's trailing u32
	// plus a walkback that counts every preceding head-equivalent transition
	// inside the current group.
	if uint32(lo) >= 1<<d.LclusterBits {
		return LclusterEntry{}, fmt.Errorf("compact entry clusterofs %d >= lcsize %d: %w",
			lo, 1<<d.LclusterBits, ErrCorrupt)
	}
	e.ClusterOfs = uint16(lo)

	if typ == disk.ZLclusterTypeHead2 {
		return LclusterEntry{}, fmt.Errorf("HEAD2 lcluster (lcn=%d, compact): %w", lcn, ErrNotImplemented)
	}

	// Walk back through the group's preceding entries, accumulating the
	// number of head-equivalent transitions. NONHEAD entries are skipped by
	// their backward delta. For big_pcluster_1 the writer encodes physical
	// block counts inline (CBLKCNT marker on NONHEAD entries) and the
	// walkback algorithm tracks those compressed block additions instead of
	// per-head increments.
	var nblk int
	j := idxInGroup - 1
	if !bigPcluster {
		nblk = 1
		for j >= 0 {
			prevLo, prevType := decodeCompactedBits(uint(lobits), groupBuf, encodebits*j)
			if prevType == disk.ZLclusterTypeNonhead {
				// Only non-last-in-group NONHEAD entries are reachable here,
				// so prevLo really is delta[0].
				j -= int(prevLo)
				if j >= 0 {
					nblk++
				}
				j--
				continue
			}
			nblk++
			j--
		}
	} else {
		nblk = 0
		for j >= 0 {
			prevLo, prevType := decodeCompactedBits(uint(lobits), groupBuf, encodebits*j)
			if prevType == disk.ZLclusterTypeNonhead {
				if prevLo&disk.ZLclusterD0CBlkCnt != 0 {
					nblk += int(prevLo &^ disk.ZLclusterD0CBlkCnt)
					j -= 2
					continue
				}
				if prevLo <= 1 {
					return LclusterEntry{}, fmt.Errorf("big_pcluster compact NONHEAD with delta=%d: %w",
						prevLo, ErrCorrupt)
				}
				j -= int(prevLo) - 2
				j--
				continue
			}
			nblk++
			j--
		}
	}
	trailing := binary.LittleEndian.Uint32(groupBuf[groupSize-4:])
	e.BlkAddr = trailing + uint32(nblk)
	return e, nil
}

func decodeCompactedBits(lobits uint, in []byte, pos int) (uint32, uint8) {
	byteOff := pos / 8
	bitShift := uint(pos & 7)
	// in is always sized to the group (≥ 8 bytes for compact-4B, 32 for
	// compact-2B) and pos+32 bits never exceeds the group's bit count.
	v := binary.LittleEndian.Uint32(in[byteOff:byteOff+4]) >> bitShift
	lo := v & ((1 << lobits) - 1)
	typ := uint8((v >> lobits) & 3)
	return lo, typ
}
