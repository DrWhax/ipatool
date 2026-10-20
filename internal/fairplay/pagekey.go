package fairplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

var fixedPageAESKey = [16]byte{0xf5, 0x88, 0xff, 0xe1, 0x89, 0xf9, 0x89, 0xf8, 0xe1, 0xf8, 0x89, 0xfe, 0x8a, 0xe1, 0xf4, 0xfe}

var (
	pageFoldPermutation = [...][8]int{{0, 1, 2, 3, 4, 5, 6, 7}, {2, 1, 0, 3, 4, 7, 6, 5}, {2, 0, 4, 1, 6, 3, 7, 5}, {1, 2, 4, 0, 7, 3, 5, 6}}
	pageFoldPairXOR     = [...]uint32{0x1e2a7432, 0x087be9c2, 0xa2eb0b97, 0x7ccc42c1}
	pageFoldOutputXOR   = [...]uint32{0x0b770182, 0xbb5b7b69, 0x5f8c31bf, 0xa6e7227a}
)

func xtime(value byte) byte {
	reduction := byte(0)
	if value&0x80 != 0 {
		reduction = 0x1b
	}
	return value<<1 ^ reduction
}

func mixColumn(input []byte) [4]byte {
	var doubled, output [4]byte
	for i := range doubled {
		doubled[i] = xtime(input[i])
	}
	output[0] = doubled[0] ^ (doubled[1] ^ input[1]) ^ input[2] ^ input[3]
	output[1] = input[0] ^ doubled[1] ^ (doubled[2] ^ input[2]) ^ input[3]
	output[2] = input[0] ^ input[1] ^ doubled[2] ^ (doubled[3] ^ input[3])
	output[3] = (doubled[0] ^ input[0]) ^ input[1] ^ input[2] ^ doubled[3]
	return output
}

func inverseMixColumn(input []byte) [4]byte {
	var doubled, quadrupled, octupled [4]byte
	for i := 0; i < 4; i++ {
		doubled[i] = xtime(input[i])
		quadrupled[i] = xtime(doubled[i])
		octupled[i] = xtime(quadrupled[i])
	}
	var m09, m0b, m0d, m0e [4]byte
	for i := 0; i < 4; i++ {
		m09[i] = octupled[i] ^ input[i]
		m0b[i] = octupled[i] ^ doubled[i] ^ input[i]
		m0d[i] = octupled[i] ^ quadrupled[i] ^ input[i]
		m0e[i] = octupled[i] ^ quadrupled[i] ^ doubled[i]
	}
	return [4]byte{
		m0e[0] ^ m0b[1] ^ m0d[2] ^ m09[3], m09[0] ^ m0e[1] ^ m0b[2] ^ m0d[3],
		m0d[0] ^ m09[1] ^ m0e[2] ^ m0b[3], m0b[0] ^ m0d[1] ^ m09[2] ^ m0e[3],
	}
}

func appMaskFromLogicalKey(logical [16]byte) [16]byte {
	var encoded [16]byte
	for column := 0; column < 4; column++ {
		word := logical[column*4 : (column+1)*4]
		reversed := [4]byte{word[3], word[2], word[1], word[0]}
		mixed := mixColumn(reversed[:])
		copy(encoded[column*4:], mixed[:])
	}
	packAdd := uint32(0x7db82c18)
	multiplier := uint32(0x594ec277)
	finalAdd := uint32(0x8603bbe8)
	finalXOR := uint32(0x07d2f11e)
	writers := [...]uint32{0x1467cdb1, 0xbea0cbf9, 0xea98d9d3, 0x477a1e20}
	var state [16]byte
	for column := 0; column < 4; column++ {
		mixed := inverseMixColumn(encoded[column*4 : (column+1)*4])
		var value uint32
		for pass := 0; pass < 4; pass++ {
			value = ((value&0x00ffffff)<<8 | uint32(mixed[pass])) + packAdd
		}
		result := (value + uint32(column+13)*multiplier + finalAdd) ^ finalXOR ^ writers[column]
		binary.BigEndian.PutUint32(state[column*4:(column+1)*4], result)
	}
	mask := [...]byte{0xE6, 0x3D, 0xC3, 0x4E, 0x30, 0x8B, 0xB3, 0x1F, 0x0C, 0xB2, 0xA1, 0x33, 0xCA, 0x49, 0x1B, 0xC0}
	for i := range state {
		state[i] ^= mask[i]
	}
	return state
}

func maskedSelect(value, gate uint32) uint32 {
	return (((value ^ 0x2919f272) &^ gate) | (gate & 0xd6e60000)) ^ 0x29192e1e
}

func feedTerm(value, maskSource uint16) uint32 {
	high := uint32(value)<<16 ^ 0xff99de03
	mask := uint32(maskSource) ^ 0xffff2207
	fallback := uint32(maskSource) & 0x21fc
	return ((high & mask) | fallback) ^ 0x23f5de6f
}

func postSquare(value, constant uint32) uint64 {
	product := uint64(value) * uint64(value)
	high := product >> 32
	correction := high - 0x0d09f9b1421db190 - ((high << 1) & 0x17bc49ce0)
	return product ^ uint64(constant) ^ correction
}

func pageFold(input [16]byte) [16]byte {
	var initial, state [8]uint16
	for i := 0; i < 8; i++ {
		initial[i] = binary.BigEndian.Uint16(input[i*2:i*2+2]) ^ 0xdc6c
		state[i] = initial[i]
	}
	for round := 0; round < 4; round++ {
		var next [8]uint16
		for pair := 0; pair < 4; pair++ {
			left := uint32(state[pageFoldPermutation[round][pair*2]] ^ 0xdc6c)
			right := uint32(state[pageFoldPermutation[round][pair*2+1]] ^ 0xdc6c)
			sum := left + right
			square := uint32(uint64(sum)*uint64(sum)) ^ pageFoldPairXOR[pair]
			carry := sum >> 16
			next[pair*2] = uint16(square ^ carry*carry ^ 0xd470)
			next[pair*2+1] = uint16((square >> 16) ^ 0xaa12)
		}
		state = next
	}
	gate3 := uint32(state[3]^0xdc6c) << 16
	gate6 := uint32(state[6]^0xdc6c) << 16
	gate7 := uint32(state[7]^0xdc6c) << 16
	combined := [4]uint32{
		maskedSelect(uint32(state[2]), gate3) + feedTerm(state[1], state[0]),
		maskedSelect(uint32(state[4]), gate6) + feedTerm(state[2], state[0]),
		maskedSelect(uint32(state[5]), gate7) + feedTerm(state[3], state[0]),
		maskedSelect(uint32(state[6]), gate7) + feedTerm(state[5], state[4]),
	}
	var output [16]byte
	for pair := 0; pair < 4; pair++ {
		square := postSquare(combined[pair], pageFoldOutputXOR[pair])
		binary.BigEndian.PutUint16(output[pair*4:pair*4+2], initial[pair*2]^uint16(square)^0x0b59)
		binary.BigEndian.PutUint16(output[pair*4+2:pair*4+4], initial[pair*2+1]^uint16(square>>16)^0x3188)
	}
	return output
}

type pageKeyDeriver struct {
	block cipher.Block
}

func newPageKeyDeriver(appMask [16]byte) *pageKeyDeriver {
	var effective [16]byte
	for i := range effective {
		effective[i] = fixedPageAESKey[i] ^ appMask[i]
	}
	block, _ := aes.NewCipher(effective[:])
	clear(effective[:])
	return &pageKeyDeriver{block: block}
}

func (deriver *pageKeyDeriver) pageKey(wrapped []byte, cryptOffset uint64) [16]byte {
	var padding [8]byte
	binary.BigEndian.PutUint64(padding[:], cryptOffset)
	var plaintext [3][16]byte
	copy(plaintext[0][:8], wrapped[8:])
	copy(plaintext[0][8:], padding[:])
	copy(plaintext[1][:], wrapped)
	copy(plaintext[2][:8], padding[:])
	copy(plaintext[2][8:], wrapped[:8])
	var encrypted [3][16]byte
	for i := range encrypted {
		deriver.block.Encrypt(encrypted[i][:], plaintext[i][:])
	}
	state := pageFold(encrypted[0])
	for i := range state {
		state[i] ^= encrypted[1][i]
	}
	state = pageFold(state)
	for i := range state {
		state[i] ^= encrypted[2][i]
	}
	return pageFold(state)
}
