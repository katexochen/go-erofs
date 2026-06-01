package erofs

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/erofs/go-erofs/internal/disk"
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
