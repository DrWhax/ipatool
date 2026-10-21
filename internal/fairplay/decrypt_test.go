package fairplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

func TestAuditARM64AcceptsARMv82HalfPrecisionSIMD(t *testing.T) {
	words := []uint32{
		0x4f001214, // fmla.8h v20, v16, v0[0]
		0x4f15127f, // fmla.8h v31, v19, v5[1]
		0x4e443694, // fmax.8h v20, v20, v4
		0x4ec537ff, // fmin.8h v31, v31, v5
	}
	page := make([]byte, pageBytes)
	for offset := 0; offset < len(page); offset += 4 {
		binary.LittleEndian.PutUint32(page[offset:offset+4], words[(offset/4)%len(words)])
	}

	valid, mnemonics := auditARM64(page)
	if valid != pageBytes/4 {
		t.Fatalf("valid ARM64 words = %d, want %d", valid, pageBytes/4)
	}
	if mnemonics["FMLA"] != 512 || mnemonics["FMAX"] != 256 || mnemonics["FMIN"] != 256 {
		t.Fatalf("unexpected mnemonic counts: %v", mnemonics)
	}
}

func TestSupplementalARM64MnemonicRejectsNearbyUnallocatedEncodings(t *testing.T) {
	for _, word := range []uint32{0x4f801214, 0x4e643694, 0x4ee537ff} {
		if mnemonic, ok := supplementalARM64Mnemonic(word); ok {
			t.Errorf("%#08x unexpectedly decoded as %s", word, mnemonic)
		}
	}
}

func TestDecryptUniversalSliceUsesAbsolutePageOffsets(t *testing.T) {
	blob, layout := signedAuditFixture(t, pageBytes, 2*pageBytes, 12, 2)
	layout.cpuType = cpuTypeARM64
	layout.cryptID = 1
	layout.cryptIDOffset = 16
	binary.LittleEndian.PutUint32(blob[layout.cryptIDOffset:], 1)

	image := encryptedImage{
		member: "Payload/Test.app/Test", supfMember: "Payload/Test.app/SC_Info/Test.supf",
		sliceOffset: 0x4000, sliceSize: uint64(len(blob)), layout: layout,
	}
	var logical [16]byte
	for index := range logical {
		logical[index] = byte(index + 1)
	}
	records := make([][32]byte, 2)
	for page := range records {
		for index := range records[page] {
			records[page][index] = byte(0x40 + page*len(records[page]) + index)
		}
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	plaintext := make([]byte, 2*pageBytes)
	for page := range records {
		key := deriver.pageKey(
			records[page][:16],
			image.sliceOffset+uint64(layout.cryptOffset)+uint64(page*pageBytes),
		)
		block, err := aes.NewCipher(key[:])
		if err != nil {
			t.Fatal(err)
		}
		start := int(layout.cryptOffset) + page*pageBytes
		cipher.NewCBCEncrypter(block, records[page][16:]).CryptBlocks(
			blob[start:start+pageBytes], plaintext[page*pageBytes:(page+1)*pageBytes],
		)
	}

	directory := blob[int(layout.signatureOffset)+20:]
	hashOffset, hashSize := 44, 32
	for slot := 0; slot < int(layout.signatureOffset)/pageBytes; slot++ {
		hash, err := hashCodePage(2, blob[slot*pageBytes:(slot+1)*pageBytes])
		if err != nil {
			t.Fatal(err)
		}
		copy(directory[hashOffset+slot*hashSize:], hash)
	}

	encryptedHash := digest(blob)
	report, err := decryptImage(blob, image, records, mask, deriver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[pageBytes:3*pageBytes], plaintext) {
		t.Fatal("universal slice did not decrypt with each absolute page offset")
	}
	if report.EncryptedSHA256 != encryptedHash || report.DecryptedSHA256 != digest(blob) {
		t.Fatalf("unexpected image hashes: %+v", report)
	}
	if report.Architecture != "arm64" || report.FirstPageAudit != "arm64-instruction-decode" || !report.FirstPageStructurallyPlausible {
		t.Fatalf("unexpected report: %+v", report)
	}
}
