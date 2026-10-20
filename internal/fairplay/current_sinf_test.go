package fairplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentSINFModelSyntheticRoundTrip(t *testing.T) {
	model, err := parseCurrentSINFModel(currentSINFModelPack)
	if err != nil {
		t.Fatal(err)
	}
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	types := [...]string{"key ", "iviv", "tmpr", "righ", "name"}
	sizes := [...]int{24, 24, 24, 88, 264}
	plaintext := make([]byte, 0, 424)
	for index, typ := range types {
		atom := make([]byte, sizes[index])
		binary.BigEndian.PutUint32(atom[:4], uint32(len(atom)))
		copy(atom[4:8], typ)
		if index == 0 {
			copy(atom[8:], innerKey[:])
		}
		plaintext = append(plaintext, atom...)
	}
	iv := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	block, err := aes.NewCipher(model.key[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, 416)
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, plaintext[:len(ciphertext)])
	logical := append(append([]byte(nil), iv[:]...), ciphertext...)
	source := make([]byte, len(logical)+8)
	for index, value := range logical {
		position := index % aes.BlockSize
		external := -1
		for candidate, decoded := range model.inputDecode[position*256 : (position+1)*256] {
			if decoded == value {
				external = candidate
				break
			}
		}
		if external < 0 {
			t.Fatalf("input table %d cannot encode %#x", position, value)
		}
		source[index] = byte(external) ^ model.whitening[position]
	}
	observed, err := currentSINFPrivateKey(model, source)
	if err != nil {
		t.Fatal(err)
	}
	if observed != innerKey {
		t.Fatalf("inner key changed: %x", observed)
	}
	wantLogical := logicalFromInnerKey(innerKey)
	gotLogical, _, err := currentSINFLogicalKey(source)
	if err != nil {
		t.Fatal(err)
	}
	if gotLogical != wantLogical {
		t.Fatalf("logical key changed: %x", gotLogical)
	}
}

func TestCurrentSINFModelValidation(t *testing.T) {
	model, err := parseCurrentSINFModel(currentSINFModelPack)
	if err != nil {
		t.Fatal(err)
	}
	if model.key == [16]byte{} || model.whitening == [16]byte{} {
		t.Fatal("embedded current SINF model is empty")
	}
	for _, offset := range []int{0, 8, 12, 16, 48, 64, 80, len(currentSINFModelPack) - 1} {
		mutated := append([]byte(nil), currentSINFModelPack...)
		mutated[offset] ^= 1
		if _, err := parseCurrentSINFModel(mutated); err == nil {
			t.Fatalf("model corruption at %#x was accepted", offset)
		}
	}
}

func TestCurrentSINFMacAndIPhoneFixtures(t *testing.T) {
	workspace, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(workspace, "artifacts/fairplay/cross-account-9292-current-mac-state-20261018-1")
	fixtures := []struct {
		sinf, logical string
	}{
		{"9292.sinf", "logical-key.bin"},
		{"9292.iphone.sinf", "iphone-logical-key.bin"},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.sinf, func(t *testing.T) {
			sinf, readErr := os.ReadFile(filepath.Join(root, fixture.sinf))
			if os.IsNotExist(readErr) {
				t.Skip("private current-SINF fixture is unavailable")
			}
			if readErr != nil {
				t.Fatal(readErr)
			}
			expected, readErr := os.ReadFile(filepath.Join(root, fixture.logical))
			if readErr != nil {
				t.Fatal(readErr)
			}
			material, resolveErr := ResolveLogicalKey(sinf)
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if !bytes.Equal(material.LogicalKey[:], expected) {
				t.Fatal("portable current-SINF logical key differs from native fixed84 capture")
			}
			if material.Evidence["provider_kind"] != "current-sinf-whitebox-direct-v1" ||
				material.Evidence["runtime_hardware_calls"] != 0 {
				t.Fatalf("unexpected evidence: %#v", material.Evidence)
			}
		})
	}
}

func TestCurrentSINFRejectsMutation(t *testing.T) {
	workspace, err := filepath.Abs("../../../../..")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(workspace, "artifacts/fairplay/cross-account-9292-current-mac-state-20261018-1/9292.iphone.sinf")
	sinf, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		t.Skip("private current-SINF fixture is unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	fields, err := parseSINFFields(sinf)
	if err != nil {
		t.Fatal(err)
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		t.Fatal(err)
	}
	private = append([]byte(nil), private...)
	private[31] ^= 1
	_, _, err = currentSINFLogicalKey(private)
	if !errors.Is(err, errCurrentSINFProfileMismatch) {
		t.Fatalf("mutated current SINF returned %v", err)
	}
}
