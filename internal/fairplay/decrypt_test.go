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

func TestDecryptUniversalSliceUsesAbsoluteCryptOffset(t *testing.T) {
	blob, layout := signedAuditFixture(t, pageBytes, pageBytes, 12, 2)
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
	records := make([][32]byte, 1)
	for index := range records[0] {
		records[0][index] = byte(0x40 + index)
	}
	mask := appMaskFromLogicalKey(logical)
	deriver := newPageKeyDeriver(mask)
	key := deriver.pageKey(records[0][:16], image.sliceOffset+uint64(layout.cryptOffset))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	plaintext := make([]byte, pageBytes)
	cipher.NewCBCEncrypter(block, records[0][16:]).CryptBlocks(blob[pageBytes:2*pageBytes], plaintext)

	directory := blob[int(layout.signatureOffset)+20:]
	hashOffset, hashSize := 44, 32
	for slot := 0; slot < 2; slot++ {
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
	if !bytes.Equal(blob[pageBytes:2*pageBytes], plaintext) {
		t.Fatal("universal slice did not decrypt with its absolute crypt offset")
	}
	if report.EncryptedSHA256 != encryptedHash || report.DecryptedSHA256 != digest(blob) {
		t.Fatalf("unexpected image hashes: %+v", report)
	}
	if report.Architecture != "arm64" || report.FirstPageAudit != "arm64-instruction-decode" || !report.FirstPageStructurallyPlausible {
		t.Fatalf("unexpected report: %+v", report)
	}
}
