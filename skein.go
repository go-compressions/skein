// Package skein implements the Skein-512 hash (Skein 1.3, the NIST SHA-3
// round-3 candidate by Ferguson, Lucks, Schneier, Whiting et al.) in pure Go,
// with the optional key (MAC) pre-processing and an arbitrary output length.
//
// It is a port of the OpenZFS implementation (zfs-2.3.0,
// module/icp/algs/skein/skein.c and skein_block.c, Doug Whiting, public
// domain), restricted to the 512-bit state. ZFS uses it as Skein-512-256
// keyed with the 32-byte pool checksum salt:
//
//	d := skein.New(256, salt)   // skein_zfs.c:84, Skein_512_InitExt
//	d.Write(block)
//	sum := d.Sum(nil)           // skein_zfs.c:53, Skein_512_Final
//
// New(256, nil) is plain Skein-512-256.
package skein

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	// BlockSize is the Skein-512 block size in bytes
	// (SKEIN_512_BLOCK_BYTES).
	BlockSize = 64

	// skein_impl.h:109 SKEIN_KS_PARITY.
	ksParity = 0x1BD11BDAA9FC1A22
	// skein_impl.h:108 SKEIN_SCHEMA_VER, version 1 with id string "SHA3".
	schemaVer = 0x0000000133414853
	// skein_impl.h:111 SKEIN_CFG_STR_LEN.
	cfgStrLen = 4 * 8

	// skein_impl.h:56-57 and 65-72: tweak flags and block types, as they
	// sit in T[1] (bit 126 is bit 62 of the high word, and so on).
	t1First = uint64(1) << (126 - 64)
	t1Final = uint64(1) << (127 - 64)
	typeKey = uint64(0) << (120 - 64)
	typeCfg = uint64(4) << (120 - 64)
	typeMsg = uint64(48) << (120 - 64)
	typeOut = uint64(63) << (120 - 64)
)

// rot holds the Threefish-512 rotation constants, skein_impl.h:228-235
// (R_512_<round>_<pair>).
var rot = [8][4]int{
	{46, 36, 19, 37},
	{33, 27, 14, 42},
	{17, 49, 36, 39},
	{44, 9, 54, 56},
	{39, 30, 34, 24},
	{13, 50, 10, 17},
	{25, 29, 39, 43},
	{8, 35, 56, 22},
}

// perm holds the word pairing of rounds 0..3 (repeating), the first
// arguments of R512 in skein_block.c:395-398 and 400-403.
var perm = [4][8]int{
	{0, 1, 2, 3, 4, 5, 6, 7},
	{2, 1, 4, 7, 6, 5, 0, 3},
	{4, 1, 6, 3, 0, 5, 2, 7},
	{6, 1, 0, 7, 2, 5, 4, 3},
}

// Digest is a Skein-512 hash state. It implements hash.Hash.
type Digest struct {
	x       [8]uint64
	t       [2]uint64
	b       [BlockSize]byte
	bCnt    int
	outBits int
	key     []byte
}

var _ hash.Hash = (*Digest)(nil)

// New returns a Skein-512 digest producing outBits bits of output, keyed with
// key when len(key) > 0 (Skein_512_InitExt with treeInfo 0). outBits must be
// positive.
func New(outBits int, key []byte) *Digest {
	if outBits <= 0 {
		panic("skein: output length must be positive")
	}
	d := &Digest{outBits: outBits, key: append([]byte(nil), key...)}
	d.Reset()
	return d
}

// Reset restores the state New produced (Skein_512_InitExt, skein.c:316-379).
func (d *Digest) Reset() {
	d.x = [8]uint64{}
	if len(d.key) > 0 {
		// Mini-Init: hash the key as a KEY-type message and take the
		// 512-bit result as the chaining value.
		d.startNewType(typeKey)
		d.bCnt = 0
		d.Write(d.key)
		var out [BlockSize]byte
		d.finalPad(&out)
		for i := range d.x {
			d.x[i] = binary.LittleEndian.Uint64(out[8*i:])
		}
	}
	// Config block: schema version, output length in bits, tree info 0.
	d.startNewType(typeCfg | t1Final)
	var cfg [BlockSize]byte
	binary.LittleEndian.PutUint64(cfg[0:], schemaVer)
	binary.LittleEndian.PutUint64(cfg[8:], uint64(d.outBits))
	d.process(cfg[:], 1, cfgStrLen)
	d.bCnt = 0
	d.startNewType(typeMsg)
}

func (d *Digest) startNewType(t1 uint64) {
	d.t[0] = 0
	d.t[1] = t1First | t1
	d.bCnt = 0
}

// Size returns the output size in bytes, Sum's append length.
func (d *Digest) Size() int { return (d.outBits + 7) >> 3 }

// BlockSize returns the Skein-512 block size.
func (d *Digest) BlockSize() int { return BlockSize }

// Clone returns an independent copy of d, the analogue of the ZFS context
// template copy (memcpy(&ctx, ctx_template, ...)).
func (d *Digest) Clone() *Digest {
	c := *d
	return &c
}

// Write absorbs p (Skein_512_Update, skein.c:383-430). The last block is
// always held back so that Sum can flag it final.
func (d *Digest) Write(p []byte) (int, error) {
	n := len(p)
	if len(p)+d.bCnt > BlockSize {
		if d.bCnt > 0 {
			k := BlockSize - d.bCnt
			copy(d.b[d.bCnt:], p[:k])
			p = p[k:]
			d.process(d.b[:], 1, BlockSize)
			d.bCnt = 0
		}
		if len(p) > BlockSize {
			blocks := (len(p) - 1) / BlockSize
			d.process(p, blocks, BlockSize)
			p = p[blocks*BlockSize:]
		}
	}
	d.bCnt += copy(d.b[d.bCnt:], p)
	return n, nil
}

// finalPad is Skein_512_Final_Pad, skein.c:740-757: it processes the buffered
// block as the final one and writes the 64-byte state.
func (d *Digest) finalPad(out *[BlockSize]byte) {
	d.t[1] |= t1Final
	clear(d.b[d.bCnt:])
	d.process(d.b[:], 1, uint64(d.bCnt))
	for i, v := range d.x {
		binary.LittleEndian.PutUint64(out[8*i:], v)
	}
}

// Sum appends the digest to in without changing d (Skein_512_Final,
// skein.c:436-480, run on a copy).
func (d *Digest) Sum(in []byte) []byte {
	c := *d
	c.t[1] |= t1Final
	clear(c.b[c.bCnt:])
	c.process(c.b[:], 1, uint64(c.bCnt))

	byteCnt := (c.outBits + 7) >> 3
	// Threefish in counter mode.
	clear(c.b[:])
	saved := c.x
	for i := 0; i*BlockSize < byteCnt; i++ {
		binary.LittleEndian.PutUint64(c.b[:], uint64(i))
		c.startNewType(typeOut | t1Final)
		c.process(c.b[:], 1, 8)
		n := byteCnt - i*BlockSize
		if n > BlockSize {
			n = BlockSize
		}
		var blk [BlockSize]byte
		for j, v := range c.x {
			binary.LittleEndian.PutUint64(blk[8*j:], v)
		}
		in = append(in, blk[:n]...)
		c.x = saved
	}
	return in
}

// processLoop is the readable, table-driven form of Skein_512_Process_Block
// (skein_block.c:267-): blkCnt blocks of p, adding byteCntAdd to the
// processed-length tweak per block. process below is the unrolled form used
// everywhere; a test asserts the two agree.
func (d *Digest) processLoop(p []byte, blkCnt int, byteCntAdd uint64) {
	var ks [9]uint64
	var ts [3]uint64
	var w, x [8]uint64
	ts[0], ts[1] = d.t[0], d.t[1]
	for ; blkCnt > 0; blkCnt-- {
		ts[0] += byteCntAdd
		copy(ks[:8], d.x[:])
		ks[8] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^ ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ ksParity
		ts[2] = ts[0] ^ ts[1]
		for i := range w {
			w[i] = binary.LittleEndian.Uint64(p[8*i:])
		}
		p = p[BlockSize:]

		// first full key injection
		for i := range x {
			x[i] = w[i] + ks[i]
		}
		x[5] += ts[0]
		x[6] += ts[1]

		for r := 0; r < 72; r++ {
			pm := &perm[r&3]
			rt := &rot[r&7]
			for j := 0; j < 4; j++ {
				a, b := pm[2*j], pm[2*j+1]
				x[a] += x[b]
				x[b] = bits.RotateLeft64(x[b], rt[j]) ^ x[a]
			}
			if r&3 == 3 { // key injection, I512(R) with R+1 = s
				s := r>>2 + 1
				for i := 0; i < 8; i++ {
					x[i] += ks[(s+i)%9]
				}
				x[5] += ts[s%3]
				x[6] += ts[(s+1)%3]
				x[7] += uint64(s)
			}
		}
		// feedforward
		for i := range x {
			d.x[i] = x[i] ^ w[i]
		}
		ts[1] &^= t1First
	}
	d.t[0], d.t[1] = ts[0], ts[1]
}

// process is Skein_512_Process_Block with the 72 rounds unrolled by hand into
// nine groups of eight (R512_8_rounds, skein_block.c:394-404), the state held
// in locals and the rotation counts constant.
func (d *Digest) process(p []byte, blkCnt int, byteCntAdd uint64) {
	// ksx and tsx are the key and tweak schedules unrolled over the 19
	// injections, the "rotation" arrays of the looping C version.
	var ksx [27]uint64
	var tsx [21]uint64
	ts0, ts1 := d.t[0], d.t[1]
	for ; blkCnt > 0; blkCnt-- {
		ts0 += byteCntAdd
		copy(ksx[:8], d.x[:])
		ksx[8] = ksx[0] ^ ksx[1] ^ ksx[2] ^ ksx[3] ^ ksx[4] ^ ksx[5] ^ ksx[6] ^ ksx[7] ^ ksParity
		for i := 9; i < len(ksx); i++ {
			ksx[i] = ksx[i-9]
		}
		tsx[0], tsx[1], tsx[2] = ts0, ts1, ts0^ts1
		for i := 3; i < len(tsx); i++ {
			tsx[i] = tsx[i-3]
		}
		w0 := binary.LittleEndian.Uint64(p[0:])
		w1 := binary.LittleEndian.Uint64(p[8:])
		w2 := binary.LittleEndian.Uint64(p[16:])
		w3 := binary.LittleEndian.Uint64(p[24:])
		w4 := binary.LittleEndian.Uint64(p[32:])
		w5 := binary.LittleEndian.Uint64(p[40:])
		w6 := binary.LittleEndian.Uint64(p[48:])
		w7 := binary.LittleEndian.Uint64(p[56:])
		p = p[BlockSize:]

		x0, x1, x2, x3 := w0+ksx[0], w1+ksx[1], w2+ksx[2], w3+ksx[3]
		x4, x5, x6, x7 := w4+ksx[4], w5+ksx[5]+ts0, w6+ksx[6]+ts1, w7+ksx[7]

		for s := 1; s <= 17; s += 2 {
			x0 += x1
			x1 = bits.RotateLeft64(x1, 46) ^ x0
			x2 += x3
			x3 = bits.RotateLeft64(x3, 36) ^ x2
			x4 += x5
			x5 = bits.RotateLeft64(x5, 19) ^ x4
			x6 += x7
			x7 = bits.RotateLeft64(x7, 37) ^ x6

			x2 += x1
			x1 = bits.RotateLeft64(x1, 33) ^ x2
			x4 += x7
			x7 = bits.RotateLeft64(x7, 27) ^ x4
			x6 += x5
			x5 = bits.RotateLeft64(x5, 14) ^ x6
			x0 += x3
			x3 = bits.RotateLeft64(x3, 42) ^ x0

			x4 += x1
			x1 = bits.RotateLeft64(x1, 17) ^ x4
			x6 += x3
			x3 = bits.RotateLeft64(x3, 49) ^ x6
			x0 += x5
			x5 = bits.RotateLeft64(x5, 36) ^ x0
			x2 += x7
			x7 = bits.RotateLeft64(x7, 39) ^ x2

			x6 += x1
			x1 = bits.RotateLeft64(x1, 44) ^ x6
			x0 += x7
			x7 = bits.RotateLeft64(x7, 9) ^ x0
			x2 += x5
			x5 = bits.RotateLeft64(x5, 54) ^ x2
			x4 += x3
			x3 = bits.RotateLeft64(x3, 56) ^ x4

			x0 += ksx[s]
			x1 += ksx[s+1]
			x2 += ksx[s+2]
			x3 += ksx[s+3]
			x4 += ksx[s+4]
			x5 += ksx[s+5] + tsx[s]
			x6 += ksx[s+6] + tsx[s+1]
			x7 += ksx[s+7] + uint64(s)

			x0 += x1
			x1 = bits.RotateLeft64(x1, 39) ^ x0
			x2 += x3
			x3 = bits.RotateLeft64(x3, 30) ^ x2
			x4 += x5
			x5 = bits.RotateLeft64(x5, 34) ^ x4
			x6 += x7
			x7 = bits.RotateLeft64(x7, 24) ^ x6

			x2 += x1
			x1 = bits.RotateLeft64(x1, 13) ^ x2
			x4 += x7
			x7 = bits.RotateLeft64(x7, 50) ^ x4
			x6 += x5
			x5 = bits.RotateLeft64(x5, 10) ^ x6
			x0 += x3
			x3 = bits.RotateLeft64(x3, 17) ^ x0

			x4 += x1
			x1 = bits.RotateLeft64(x1, 25) ^ x4
			x6 += x3
			x3 = bits.RotateLeft64(x3, 29) ^ x6
			x0 += x5
			x5 = bits.RotateLeft64(x5, 39) ^ x0
			x2 += x7
			x7 = bits.RotateLeft64(x7, 43) ^ x2

			x6 += x1
			x1 = bits.RotateLeft64(x1, 8) ^ x6
			x0 += x7
			x7 = bits.RotateLeft64(x7, 35) ^ x0
			x2 += x5
			x5 = bits.RotateLeft64(x5, 56) ^ x2
			x4 += x3
			x3 = bits.RotateLeft64(x3, 22) ^ x4

			x0 += ksx[s+1]
			x1 += ksx[s+2]
			x2 += ksx[s+3]
			x3 += ksx[s+4]
			x4 += ksx[s+5]
			x5 += ksx[s+6] + tsx[s+1]
			x6 += ksx[s+7] + tsx[s+2]
			x7 += ksx[s+8] + uint64(s+1)
		}
		d.x[0], d.x[1], d.x[2], d.x[3] = x0^w0, x1^w1, x2^w2, x3^w3
		d.x[4], d.x[5], d.x[6], d.x[7] = x4^w4, x5^w5, x6^w6, x7^w7
		ts1 &^= t1First
	}
	d.t[0], d.t[1] = ts0, ts1
}
