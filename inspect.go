package erofs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"

	"github.com/erofs/go-erofs/internal/disk"
	"github.com/erofs/go-erofs/internal/zerofs"
)

// Dump writes a textual, diff-friendly description of every on-disk structure
// in the image referenced by r to w. The output is line-based key:value text
// with deterministic ordering (superblock fields in struct order, image-level
// sections first, then inodes in DFS-by-path order), so that two dumps can be
// compared with diff(1).
//
// Dump is intended for debugging reproducibility issues where two images have
// the same logical content but differ on the filesystem layer (NIDs, layout
// choices, xattr encoding, compression cluster boundaries, etc.).
func Dump(r io.ReaderAt, w io.Writer, opts ...OpenOpt) error {
	fsys, err := Open(r, opts...)
	if err != nil {
		return err
	}
	img, ok := fsys.(*image)
	if !ok {
		return fmt.Errorf("erofs.Dump: Open returned unexpected type %T", fsys)
	}
	if err := dumpSuperblock(img, w); err != nil {
		return err
	}
	if err := dumpComprCfgs(img, w); err != nil {
		return err
	}
	if err := dumpDevices(img, w); err != nil {
		return err
	}
	if err := dumpLongXattrPrefixes(img, w); err != nil {
		return err
	}
	if err := dumpInodes(img, w); err != nil {
		return err
	}
	return nil
}

func dumpSuperblock(img *image, w io.Writer) error {
	sb := &img.sb
	fmt.Fprintln(w, "[superblock]")
	fmt.Fprintf(w, "  magic: 0x%08x\n", sb.MagicNumber)
	fmt.Fprintf(w, "  checksum: 0x%08x\n", sb.Checksum)
	fmt.Fprintf(w, "  feature_compat: 0x%08x\n", sb.FeatureCompat)
	fmt.Fprintf(w, "  feature_incompat: 0x%08x [%s]\n",
		sb.FeatureIncompat, formatFeatureIncompat(sb.FeatureIncompat))
	fmt.Fprintf(w, "  blk_size_bits: %d (blk_size=%d)\n", sb.BlkSizeBits, 1<<sb.BlkSizeBits)
	fmt.Fprintf(w, "  ext_slots: %d\n", sb.ExtSlots)
	fmt.Fprintf(w, "  root_nid: %d\n", sb.RootNid)
	fmt.Fprintf(w, "  inos: %d\n", sb.Inos)
	fmt.Fprintf(w, "  build_time: %d  build_time_ns: %d\n", sb.BuildTime, sb.BuildTimeNs)
	fmt.Fprintf(w, "  blocks: %d\n", sb.Blocks)
	fmt.Fprintf(w, "  meta_blk_addr: %d\n", sb.MetaBlkAddr)
	fmt.Fprintf(w, "  xattr_blk_addr: %d\n", sb.XattrBlkAddr)
	fmt.Fprintf(w, "  uuid: %s\n", formatUUID(sb.UUID))
	fmt.Fprintf(w, "  volume_name: %q\n", trimNul(sb.VolumeName[:]))
	fmt.Fprintf(w, "  compr_algs: 0x%04x [%s]\n",
		sb.ComprAlgs, formatComprAlgs(sb))
	fmt.Fprintf(w, "  extra_devices: %d\n", sb.ExtraDevices)
	fmt.Fprintf(w, "  devt_slot_off: %d\n", sb.DevtSlotOff)
	fmt.Fprintf(w, "  dir_blk_bits: %d\n", sb.DirBlkBits)
	fmt.Fprintf(w, "  xattr_prefix_count: %d\n", sb.XattrPrefixCount)
	fmt.Fprintf(w, "  xattr_prefix_start: %d\n", sb.XattrPrefixStart)
	fmt.Fprintf(w, "  packed_nid: %d\n", sb.PackedNid)
	fmt.Fprintf(w, "  xattr_filter_res: %d\n", sb.XattrFilterRes)
	return nil
}

func dumpComprCfgs(img *image, w io.Writer) error {
	// COMPR_CFGS records are only present when the FeatureIncompatComprCfgs
	// bit is set. Without it, the ComprAlgs field is reinterpreted as
	// lz4_max_distance; skip the section in that case.
	if img.sb.FeatureIncompat&disk.FeatureIncompatComprCfgs == 0 {
		return nil
	}
	if img.sb.ComprAlgs == 0 {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[compr_cfgs]")
	if img.sb.ComprAlgs&disk.ComprAlgLZ4 != 0 {
		fmt.Fprintf(w, "  lz4: max_distance=%d max_pcluster_blks=%d\n",
			img.lz4Cfg.MaxDistance, img.lz4Cfg.MaxPclusterBlks)
	}
	if img.zstdCfgPresent {
		fmt.Fprintf(w, "  zstd: format=%d window_log=%d (window=%d)\n",
			img.zstdCfg.Format, img.zstdCfg.WindowLog, 1<<(uint(img.zstdCfg.WindowLog)+10))
	}
	return nil
}

func dumpDevices(img *image, w io.Writer) error {
	if len(img.devices) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[devices]")
	for i, d := range img.devices {
		// Re-read the slot for the tag bytes; the parsed deviceInfo does not
		// retain them.
		var slotBuf [disk.SizeDeviceSlot]byte
		off := int64(img.sb.DevtSlotOff)*disk.SizeDeviceSlot + int64(i)*disk.SizeDeviceSlot
		if _, err := img.meta.ReadAt(slotBuf[:], off); err != nil {
			return fmt.Errorf("read device slot %d: %w", i, err)
		}
		// Tag is the first 64 bytes of the slot.
		fmt.Fprintf(w, "  device %d: blocks=%d mapped_blkaddr=%d tag=%x\n",
			i, d.blocks, d.mappedBlkAddr, slotBuf[:64])
	}
	return nil
}

func dumpLongXattrPrefixes(img *image, w io.Writer) error {
	if img.sb.XattrPrefixCount == 0 {
		return nil
	}
	if err := img.loadLongPrefixes(); err != nil {
		return fmt.Errorf("load long xattr prefixes: %w", err)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "[xattr_prefixes]")
	for i, p := range img.longPrefixes {
		// p == base + infix; we can recover base by matching against the
		// known short-prefix table.
		base, infix := splitLongPrefix(p)
		fmt.Fprintf(w, "  index=%d base=%q infix=%q -> %q\n", i, base, infix, p)
	}
	return nil
}

// splitLongPrefix decomposes a long xattr prefix into its (short-prefix base,
// infix) parts by matching the leading bytes against the standard prefix
// table. Returns ("", full) if no short-prefix base matches.
func splitLongPrefix(p string) (base, infix string) {
	for i := uint8(1); i <= 6; i++ {
		b := xattrIndex(i).String()
		if strings.HasPrefix(p, b) {
			return b, p[len(b):]
		}
	}
	return "", p
}

func formatFeatureIncompat(f uint32) string {
	type bit struct {
		mask uint32
		name string
	}
	bits := []bit{
		{disk.FeatureIncompatLZ4_0Padding, "LZ4_0_PADDING"},
		{disk.FeatureIncompatComprCfgs, "COMPR_CFGS"},
		{disk.FeatureIncompatChunkedFile, "CHUNKED_FILE"},
		{disk.FeatureIncompatDeviceTable, "DEVICE_TABLE"},
		{disk.FeatureIncompatFragments, "FRAGMENTS"},
		{disk.FeatureIncompatXattrPrefixes, "XATTR_PREFIXES"},
	}
	var parts []string
	for _, b := range bits {
		if f&b.mask != 0 {
			parts = append(parts, b.name)
		}
	}
	rem := f &^ disk.FeatureIncompatAll
	if rem != 0 {
		parts = append(parts, fmt.Sprintf("UNKNOWN(0x%x)", rem))
	}
	return strings.Join(parts, "|")
}

func formatComprAlgs(sb *disk.SuperBlock) string {
	if sb.FeatureIncompat&disk.FeatureIncompatComprCfgs == 0 {
		// Without COMPR_CFGS this field is lz4_max_distance, not a bitmap.
		return fmt.Sprintf("lz4_max_distance=%d", sb.ComprAlgs)
	}
	bits := []struct {
		mask uint16
		name string
	}{
		{disk.ComprAlgLZ4, "LZ4"},
		{disk.ComprAlgLZMA, "LZMA"},
		{disk.ComprAlgDeflate, "DEFLATE"},
		{disk.ComprAlgZstd, "ZSTD"},
	}
	var parts []string
	for _, b := range bits {
		if sb.ComprAlgs&b.mask != 0 {
			parts = append(parts, b.name)
		}
	}
	return strings.Join(parts, "|")
}

func formatUUID(u [16]uint8) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		u[0], u[1], u[2], u[3],
		u[4], u[5],
		u[6], u[7],
		u[8], u[9],
		u[10], u[11], u[12], u[13], u[14], u[15])
}

func trimNul(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// dumpInodes walks the image via fs.WalkDir and emits one [inode] section per
// path in DFS lexical order. Each section prints the parsed inode core plus a
// layout-specific interpretation of the inode_data field.
func dumpInodes(img *image, w io.Writer) error {
	return fs.WalkDir(img, ".", func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		ino, err := img.inodeForPath(p)
		if err != nil {
			return fmt.Errorf("read inode for %q: %w", p, err)
		}
		defer img.releaseInodeCache(ino)
		fmt.Fprintln(w)
		if err := dumpInodeCore(img, w, dumpPath(p), ino); err != nil {
			return err
		}
		if ino.rawMode&disk.StatTypeMask == disk.StatTypeDir {
			if err := dumpDirents(img, w, ino); err != nil {
				return err
			}
		}
		if ino.xsize > 0 {
			if err := dumpXattrs(img, w, ino); err != nil {
				return err
			}
		}
		if ino.inodeLayout == disk.LayoutChunkBased {
			if err := dumpChunks(img, w, ino); err != nil {
				return err
			}
		}
		if ino.inodeLayout == disk.LayoutCompressedFull ||
			ino.inodeLayout == disk.LayoutCompressedCompact {
			if err := dumpCompressed(img, w, ino); err != nil {
				return err
			}
		}
		return nil
	})
}

// inodeForPath resolves a fs.WalkDir-style path to an *inode, without
// following the final component (so symlinks are dumped as themselves).
func (img *image) inodeForPath(p string) (*inode, error) {
	nid, ftype, basename, err := img.resolve("dump", p, false)
	if err != nil {
		return nil, err
	}
	f := &file{img: img, name: basename, nid: nid, ftype: ftype}
	return f.readInfo()
}

// releaseInodeCache returns any block held by ino.cached to the pool. Callers
// must invoke this after consuming an inode read for dumping.
func (img *image) releaseInodeCache(ino *inode) {
	if ino != nil && ino.cached != nil {
		img.putBlock(ino.cached)
		ino.cached = nil
	}
}

// dumpPath rewrites fs.WalkDir's relative paths to absolute display form,
// preserving "/" for the root.
func dumpPath(p string) string {
	if p == "" || p == "." {
		return "/"
	}
	return "/" + p
}

func dumpInodeCore(img *image, w io.Writer, displayPath string, ino *inode) error {
	mode := disk.EroFSModeToGoFileMode(ino.rawMode)
	fmt.Fprintf(w, "[inode] path=%s nid=%d layout=%s(%d) compact=%t\n",
		displayPath, ino.nid, layoutName(ino.inodeLayout), ino.inodeLayout,
		ino.icsize == disk.SizeInodeCompact)
	fmt.Fprintf(w, "  raw_mode=0o%o mode=%s\n", ino.rawMode, mode)
	fmt.Fprintf(w, "  uid=%d gid=%d size=%d nlink=%d\n", ino.uid, ino.gid, ino.size, ino.nlink)
	fmt.Fprintf(w, "  mtime=%d mtime_ns=%d\n", ino.mtime, ino.mtimeNs)
	fmt.Fprintf(w, "  icsize=%d xsize=%d\n", ino.icsize, ino.xsize)
	fmt.Fprintf(w, "  inode_data=0x%08x%s\n", ino.inodeData, inodeDataHint(ino))
	return nil
}

// inodeDataHint returns a parenthesised, layout-specific decoding of the
// inode_data field, or "" if no interpretation applies. The hint helps a
// reader interpret the raw word quickly when diffing.
func inodeDataHint(ino *inode) string {
	switch ino.rawMode & disk.StatTypeMask {
	case disk.StatTypeChrdev, disk.StatTypeBlkdev, disk.StatTypeFifo, disk.StatTypeSock:
		return fmt.Sprintf(" (rdev=0x%x)", ino.inodeData)
	}
	switch ino.inodeLayout {
	case disk.LayoutFlatPlain, disk.LayoutFlatInline:
		return fmt.Sprintf(" (data_blkaddr=%d)", ino.inodeData)
	case disk.LayoutChunkBased:
		fmtBits := uint16(ino.inodeData) & disk.LayoutChunkFormatBits
		flags := uint16(ino.inodeData) &^ uint16(disk.LayoutChunkFormatBits)
		var bits []string
		if flags&disk.LayoutChunkFormatIndexes != 0 {
			bits = append(bits, "INDEXES")
		}
		if flags&disk.LayoutChunkFormat48Bit != 0 {
			bits = append(bits, "48BIT")
		}
		flagStr := ""
		if len(bits) > 0 {
			flagStr = " [" + strings.Join(bits, "|") + "]"
		}
		return fmt.Sprintf(" (chunk_format_bits=%d%s)", fmtBits, flagStr)
	}
	return ""
}

// dumpDirents emits the on-disk dirent layout of a directory inode, one block
// at a time in physical order. Entries are printed in storage order (including
// "." and "..") so the layout is faithfully reproduced; this is the dimension
// where directory packing differences become visible across two images that
// otherwise hold the same logical content.
func dumpDirents(img *image, w io.Writer, ino *inode) error {
	if ino.size == 0 {
		return nil
	}
	blkSize := int64(1) << img.sb.BlkSizeBits
	nblocks := int((ino.size + blkSize - 1) / blkSize)
	fmt.Fprintln(w, "  dirents:")
	for bn := 0; bn < nblocks; bn++ {
		pos := int64(bn) << img.sb.BlkSizeBits
		b, err := img.loadBlock(ino, pos)
		if err != nil {
			return fmt.Errorf("load dirent block %d for nid %d: %w", bn, ino.nid, err)
		}
		buf := b.bytes()
		fmt.Fprintf(w, "    block %d:\n", bn)
		if len(buf) < disk.SizeDirent {
			img.putBlock(b)
			return fmt.Errorf("dirent block %d for nid %d too small (%d bytes)", bn, ino.nid, len(buf))
		}
		first, _, err := blockDirent(buf, 0, 1)
		if err != nil {
			img.putBlock(b)
			return fmt.Errorf("decode first dirent in block %d for nid %d: %w", bn, ino.nid, err)
		}
		if first.NameOff%disk.SizeDirent != 0 {
			img.putBlock(b)
			return fmt.Errorf("dirent block %d for nid %d: name_off %d not aligned to dirent size",
				bn, ino.nid, first.NameOff)
		}
		entryN := first.NameOff / disk.SizeDirent
		for i := uint16(0); i < entryN; i++ {
			de, name, err := blockDirent(buf, i, entryN)
			if err != nil {
				img.putBlock(b)
				return fmt.Errorf("decode dirent %d in block %d for nid %d: %w", i, bn, ino.nid, err)
			}
			fmt.Fprintf(w, "      [%d] name=%q nid=%d ftype=%d (%s) name_off=%d\n",
				i, string(name), de.Nid, de.FileType, ftypeName(de.FileType), de.NameOff)
		}
		img.putBlock(b)
	}
	return nil
}

// dumpCompressed emits the compressed-layout map for an inode: the raw
// z_erofs_map_header with decoded advise bits and head1/head2 algorithm
// names, every lcluster index entry, and the resolved pcluster boundaries.
//
// The header is always dumped (so unsupported features are still surfaced);
// the lcluster index and pcluster walk are only attempted if the decoder can
// be built — when parsing fails the error is reported in-line and we move on.
func dumpCompressed(img *image, w io.Writer, ino *inode) error {
	inodeAddr := img.metaStartPos() + int64(ino.nid)*disk.SizeInodeCompact
	mapHeaderAddr := alignUp8(inodeAddr + int64(ino.icsize) + int64(ino.xsize))

	var hbuf [disk.SizeZMapHeader]byte
	if _, err := img.meta.ReadAt(hbuf[:], mapHeaderAddr); err != nil {
		return fmt.Errorf("read zmap header for nid %d: %w", ino.nid, err)
	}
	var h disk.ZMapHeader
	if _, err := binary.Decode(hbuf[:], binary.LittleEndian, &h); err != nil {
		return fmt.Errorf("decode zmap header for nid %d: %w", ino.nid, err)
	}
	dumpZMapHeader(img, w, h, mapHeaderAddr)

	dec, err := img.buildZDecoder(ino)
	if err != nil {
		fmt.Fprintf(w, "  zmap: build_decoder_error: %v\n", err)
		return nil
	}
	if err := dumpLclusters(w, dec); err != nil {
		fmt.Fprintf(w, "  zmap: lcluster_error: %v\n", err)
		return nil
	}
	if err := dumpPclusters(w, dec); err != nil {
		fmt.Fprintf(w, "  zmap: pcluster_error: %v\n", err)
		return nil
	}
	return nil
}

func dumpZMapHeader(img *image, w io.Writer, h disk.ZMapHeader, addr int64) {
	lclusterBits := img.sb.BlkSizeBits + (h.ClusterBits & disk.ZClusterBitsLclusterMask)
	fmt.Fprintln(w, "  zmap_header:")
	fmt.Fprintf(w, "    addr: 0x%x\n", addr)

	// The first 4 bytes are a union. Show h_fragmentoff when the inode is
	// a fragment inode (whole file in packed inode) or has a FRAGMENT_PCLUSTER
	// tail (last pcluster in packed inode); show h_reserved1 + h_idata_size
	// when the file uses INLINE_PCLUSTER tailpacking; otherwise both halves
	// should be zero and either interpretation is shown literally.
	fragmentInode := h.ClusterBits&disk.ZClusterBitsFragmentInode != 0
	switch {
	case fragmentInode || h.Advise&disk.ZAdviseFragmentPcluster != 0:
		fragOff := uint32(h.Reserved1) | uint32(h.IdataSize)<<16
		role := "whole file in packed inode"
		if !fragmentInode {
			role = "pcluster tail in packed inode"
		}
		fmt.Fprintf(w, "    h_fragmentoff: 0x%08x (%d) [%s, packed_nid=%d]\n",
			fragOff, fragOff, role, img.sb.PackedNid)
	case h.Advise&disk.ZAdviseInlinePcluster != 0:
		fmt.Fprintf(w, "    h_reserved1: 0x%04x\n", h.Reserved1)
		fmt.Fprintf(w, "    h_idata_size: %d [tailpacking]\n", h.IdataSize)
	default:
		fmt.Fprintf(w, "    h_reserved1: 0x%04x\n", h.Reserved1)
		fmt.Fprintf(w, "    h_idata_size: %d\n", h.IdataSize)
	}

	fmt.Fprintf(w, "    advise: 0x%04x [%s]\n", h.Advise, formatZAdvise(h.Advise))
	fmt.Fprintf(w, "    algorithm_type: head1=%s(%d) head2=%s(%d) (raw=0x%02x)\n",
		algoName(h.AlgorithmType&0xF), h.AlgorithmType&0xF,
		algoName(h.AlgorithmType>>4), h.AlgorithmType>>4,
		h.AlgorithmType)
	fmt.Fprintf(w, "    cluster_bits_raw: 0x%02x [%s]\n",
		h.ClusterBits, formatZClusterBits(h.ClusterBits))
	fmt.Fprintf(w, "    lcluster_bits: %d (lcluster_size=%d)\n",
		lclusterBits, 1<<lclusterBits)
}

func formatZClusterBits(cb uint8) string {
	var parts []string
	if cb&disk.ZClusterBitsFragmentInode != 0 {
		parts = append(parts, "FRAGMENT_INODE")
	}
	return strings.Join(parts, "|")
}

func dumpLclusters(w io.Writer, dec *zerofs.Decoder) error {
	fmt.Fprintf(w, "  lclusters: count=%d index_base=0x%x\n", dec.NLclusters, dec.IndexBase)
	for i := 0; i < dec.NLclusters; i++ {
		e, err := dec.Entry(i)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		switch e.Type {
		case disk.ZLclusterTypePlain:
			fmt.Fprintf(w, "    [%d] type=plain cluster_ofs=%d blkaddr=0x%x\n",
				i, e.ClusterOfs, e.BlkAddr)
		case disk.ZLclusterTypeHead1:
			fmt.Fprintf(w, "    [%d] type=head1 cluster_ofs=%d blkaddr=0x%x\n",
				i, e.ClusterOfs, e.BlkAddr)
		case disk.ZLclusterTypeHead2:
			fmt.Fprintf(w, "    [%d] type=head2 cluster_ofs=%d blkaddr=0x%x\n",
				i, e.ClusterOfs, e.BlkAddr)
		case disk.ZLclusterTypeNonhead:
			fmt.Fprintf(w, "    [%d] type=nonhead delta_prev=%d delta_next=%d cblkcnt=%d\n",
				i, e.DeltaPrev, e.DeltaNext, e.CBlkCnt)
		default:
			fmt.Fprintf(w, "    [%d] type=unknown(%d)\n", i, e.Type)
		}
	}
	return nil
}

func dumpPclusters(w io.Writer, dec *zerofs.Decoder) error {
	if dec.Size == 0 {
		return nil
	}
	fmt.Fprintln(w, "  pclusters:")
	lcsize := dec.LclusterSize()
	seen := make(map[int]bool)
	idx := 0
	for pos := int64(0); pos < dec.Size; {
		pc, err := dec.FindPclusterForOffset(pos)
		if err != nil {
			return fmt.Errorf("find pcluster at %d: %w", pos, err)
		}
		if !seen[pc.HeadLcn] {
			seen[pc.HeadLcn] = true
			fmt.Fprintf(w, "    [%d] head_lcn=%d head_type=%s head_blk=0x%x head_ofs=%d nphys=%d log=[%d,%d)\n",
				idx, pc.HeadLcn, lclusterTypeName(pc.HeadType),
				pc.HeadBlk, pc.HeadOfs, pc.NPhysBlks,
				pc.LogStart, pc.LogStart+pc.LogLen)
			idx++
		}
		// Advance to the next lcluster boundary or end of pcluster, whichever comes first.
		next := pc.LogStart + pc.LogLen
		if next <= pos {
			// Safety: avoid infinite loop on malformed input.
			next = pos + lcsize
		}
		pos = next
	}
	return nil
}

func formatZAdvise(a uint16) string {
	bits := []struct {
		mask uint16
		name string
	}{
		{disk.ZAdviseCompacted2B, "COMPACTED_2B"},
		{disk.ZAdviseBigPcluster1, "BIG_PCLUSTER_1"},
		{disk.ZAdviseBigPcluster2, "BIG_PCLUSTER_2"},
		{disk.ZAdviseInlinePcluster, "INLINE_PCLUSTER"},
		{disk.ZAdviseInterlacedPcluster, "INTERLACED_PCLUSTER"},
		{disk.ZAdviseFragmentPcluster, "FRAGMENT_PCLUSTER"},
	}
	var parts []string
	for _, b := range bits {
		if a&b.mask != 0 {
			parts = append(parts, b.name)
		}
	}
	return strings.Join(parts, "|")
}

func algoName(id uint8) string {
	switch id {
	case disk.AlgoIDLZ4:
		return "lz4"
	case disk.AlgoIDLZMA:
		return "lzma"
	case disk.AlgoIDDeflate:
		return "deflate"
	case disk.AlgoIDZstd:
		return "zstd"
	default:
		return fmt.Sprintf("unknown(%d)", id)
	}
}

func lclusterTypeName(t uint8) string {
	switch t {
	case disk.ZLclusterTypePlain:
		return "plain"
	case disk.ZLclusterTypeHead1:
		return "head1"
	case disk.ZLclusterTypeHead2:
		return "head2"
	case disk.ZLclusterTypeNonhead:
		return "nonhead"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

// dumpChunks emits the chunk index for a chunk-based inode: format flags
// breakdown, derived chunk size, and per-chunk (device_id, physical block)
// or hole markers. The on-disk encoding is either 4-byte (legacy) or 8-byte
// (with index flag) per chunk; both are decoded.
func dumpChunks(img *image, w io.Writer, ino *inode) error {
	if ino.size == 0 {
		return nil
	}
	format := uint16(ino.inodeData)
	chunkBits := img.sb.BlkSizeBits + uint8(format&disk.LayoutChunkFormatBits)
	chunkSize := uint64(1) << chunkBits
	nchunks := int((ino.size-1)>>chunkBits) + 1

	unit := int64(4)
	if format&disk.LayoutChunkFormatIndexes != 0 {
		unit = 8
	}
	if format&disk.LayoutChunkFormat48Bit != 0 {
		// loadBlock returns ErrNotImplemented for 48-bit chunks; we surface
		// the metadata anyway since the dump is informational.
	}

	inodeStart := img.metaStartPos() + int64(ino.nid)*disk.SizeInodeCompact
	baseOffset := inodeStart + ino.flatDataOffset()
	if unit == 8 && baseOffset%8 != 0 {
		baseOffset = (baseOffset + 7) & ^int64(7)
	}

	fmt.Fprintf(w, "  chunks: chunk_bits=%d (chunk_size=%d) count=%d unit=%d\n",
		chunkBits, chunkSize, nchunks, unit)

	buf := make([]byte, nchunks*int(unit))
	if _, err := img.meta.ReadAt(buf, baseOffset); err != nil {
		return fmt.Errorf("read chunk index for nid %d: %w", ino.nid, err)
	}
	for i := 0; i < nchunks; i++ {
		off := i * int(unit)
		if unit == 8 {
			blkHi := binary.LittleEndian.Uint16(buf[off : off+2])
			devRaw := binary.LittleEndian.Uint16(buf[off+2 : off+4])
			blkLo := binary.LittleEndian.Uint32(buf[off+4 : off+8])
			if ^blkLo == 0 {
				fmt.Fprintf(w, "    [%d] hole (dev_raw=0x%04x blk_hi=0x%04x)\n", i, devRaw, blkHi)
				continue
			}
			devID := devRaw & img.deviceIDMask
			phys := (uint64(blkHi) << 32) | uint64(blkLo)
			fmt.Fprintf(w, "    [%d] dev_id=%d (raw=0x%04x) blk_addr=0x%x\n",
				i, devID, devRaw, phys)
		} else {
			raw := binary.LittleEndian.Uint32(buf[off : off+4])
			if ^raw == 0 {
				fmt.Fprintf(w, "    [%d] hole\n", i)
				continue
			}
			fmt.Fprintf(w, "    [%d] blk_addr=0x%x\n", i, raw)
		}
	}
	return nil
}

// dumpXattrs emits the on-disk xattr layout for an inode: body header, shared
// xattr references (with the resolved entry from the shared xattr block), and
// inline entries with their raw NameIndex byte decoded. Followed by a sorted
// resolved name->value listing so the on-disk view and the logical view can
// both be diffed.
func dumpXattrs(img *image, w io.Writer, ino *inode) error {
	addr := img.metaStartPos() + int64(ino.nid)*disk.SizeInodeCompact + int64(ino.icsize)
	buf := make([]byte, ino.xsize)
	if _, err := img.meta.ReadAt(buf, addr); err != nil {
		return fmt.Errorf("read xattr area for nid %d: %w", ino.nid, err)
	}
	if len(buf) < disk.SizeXattrBodyHeader {
		return fmt.Errorf("xattr area too small for nid %d (%d bytes)", ino.nid, len(buf))
	}

	var xh disk.XattrHeader
	if _, err := binary.Decode(buf[:disk.SizeXattrBodyHeader], binary.LittleEndian, &xh); err != nil {
		return fmt.Errorf("decode xattr body header for nid %d: %w", ino.nid, err)
	}
	fmt.Fprintln(w, "  xattrs:")
	fmt.Fprintf(w, "    body_header: name_filter=0x%08x shared_count=%d\n",
		xh.NameFilter, xh.SharedCount)

	pos := disk.SizeXattrBodyHeader
	resolved := make(map[string]string)

	if xh.SharedCount > 0 {
		fmt.Fprintln(w, "    shared_refs:")
		for i := uint8(0); i < xh.SharedCount; i++ {
			if pos+4 > len(buf) {
				return fmt.Errorf("xattr shared ref %d for nid %d out of range", i, ino.nid)
			}
			ref := binary.LittleEndian.Uint32(buf[pos : pos+4])
			name, value, hint, err := readSharedXattr(img, ref)
			if err != nil {
				return fmt.Errorf("read shared xattr %d (addr=0x%08x) for nid %d: %w", i, ref, ino.nid, err)
			}
			fmt.Fprintf(w, "      [%d] addr=0x%08x %s name=%q value=%q\n", i, ref, hint, name, value)
			resolved[name] = value
			pos += 4
		}
	}

	if pos < len(buf) {
		fmt.Fprintln(w, "    inline_entries:")
		idx := 0
		for pos < len(buf) {
			if pos+disk.SizeXattrEntry > len(buf) {
				return fmt.Errorf("xattr inline entry %d for nid %d truncated", idx, ino.nid)
			}
			var e disk.XattrEntry
			if _, err := binary.Decode(buf[pos:pos+disk.SizeXattrEntry], binary.LittleEndian, &e); err != nil {
				return fmt.Errorf("decode xattr entry %d for nid %d: %w", idx, ino.nid, err)
			}
			nameStart := pos + disk.SizeXattrEntry
			valueStart := nameStart + int(e.NameLen)
			valueEnd := valueStart + int(e.ValueLen)
			if valueEnd > len(buf) {
				return fmt.Errorf("xattr inline entry %d for nid %d body out of range", idx, ino.nid)
			}
			rawName := string(buf[nameStart:valueStart])
			value := string(buf[valueStart:valueEnd])
			prefix, hint, err := resolveXattrPrefix(img, e.NameIndex)
			if err != nil {
				return fmt.Errorf("xattr entry %d for nid %d: %w", idx, ino.nid, err)
			}
			fmt.Fprintf(w,
				"      [%d] name_index=0x%02x (%s) name_len=%d value_len=%d name=%q value=%q\n",
				idx, e.NameIndex, hint, e.NameLen, e.ValueLen, rawName, value)
			resolved[prefix+rawName] = value

			consumed := disk.SizeXattrEntry + int(e.NameLen) + int(e.ValueLen)
			if rem := consumed % 4; rem != 0 {
				consumed += 4 - rem
			}
			pos += consumed
			idx++
		}
	}

	if len(resolved) > 0 {
		fmt.Fprintln(w, "    resolved:")
		keys := make([]string, 0, len(resolved))
		for k := range resolved {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(w, "      %q: %q\n", k, resolved[k])
		}
	}
	return nil
}

// readSharedXattr reads a single xattr entry from the shared xattr block at
// the 4-byte unit offset addr (i.e. byte offset = xattr_blk_addr * blockSize +
// addr * 4). Returns the resolved full name, value, and a human-readable hint
// describing the on-disk NameIndex encoding.
func readSharedXattr(img *image, addr uint32) (name, value, hint string, err error) {
	off := int64(img.sb.XattrBlkAddr)<<img.sb.BlkSizeBits + int64(addr)*4
	var head [disk.SizeXattrEntry]byte
	if _, err := img.meta.ReadAt(head[:], off); err != nil {
		return "", "", "", fmt.Errorf("read shared xattr header: %w", err)
	}
	var e disk.XattrEntry
	if _, err := binary.Decode(head[:], binary.LittleEndian, &e); err != nil {
		return "", "", "", fmt.Errorf("decode shared xattr header: %w", err)
	}
	body := make([]byte, int(e.NameLen)+int(e.ValueLen))
	if _, err := img.meta.ReadAt(body, off+disk.SizeXattrEntry); err != nil {
		return "", "", "", fmt.Errorf("read shared xattr body: %w", err)
	}
	prefix, hintBase, err := resolveXattrPrefix(img, e.NameIndex)
	if err != nil {
		return "", "", "", err
	}
	rawName := string(body[:e.NameLen])
	return prefix + rawName,
		string(body[e.NameLen:]),
		fmt.Sprintf("name_index=0x%02x (%s) name_len=%d value_len=%d",
			e.NameIndex, hintBase, e.NameLen, e.ValueLen),
		nil
}

// resolveXattrPrefix returns the full prefix string for an on-disk NameIndex
// byte, plus a short hint describing whether it is a short or long prefix.
func resolveXattrPrefix(img *image, nameIndex uint8) (prefix, hint string, err error) {
	if nameIndex&0x80 != 0 {
		idx := nameIndex &^ 0x80
		p, lerr := img.getLongPrefix(idx)
		if lerr != nil {
			return "", "", fmt.Errorf("long prefix idx=%d: %w", idx, lerr)
		}
		return p, fmt.Sprintf("long, prefix_idx=%d, prefix=%q", idx, p), nil
	}
	if nameIndex == 0 {
		return "", "no prefix", nil
	}
	p := xattrIndex(nameIndex).String()
	return p, fmt.Sprintf("short, prefix=%q", p), nil
}

func ftypeName(t uint8) string {
	switch t {
	case disk.FileTypeReg:
		return "reg"
	case disk.FileTypeDir:
		return "dir"
	case disk.FileTypeChrdev:
		return "chrdev"
	case disk.FileTypeBlkdev:
		return "blkdev"
	case disk.FileTypeFifo:
		return "fifo"
	case disk.FileTypeSock:
		return "sock"
	case disk.FileTypeSymlink:
		return "symlink"
	default:
		return fmt.Sprintf("unknown(%d)", t)
	}
}

func layoutName(l uint8) string {
	switch l {
	case disk.LayoutFlatPlain:
		return "flat-plain"
	case disk.LayoutCompressedFull:
		return "compressed-full"
	case disk.LayoutFlatInline:
		return "flat-inline"
	case disk.LayoutCompressedCompact:
		return "compressed-compact"
	case disk.LayoutChunkBased:
		return "chunk-based"
	default:
		return fmt.Sprintf("unknown(%d)", l)
	}
}
