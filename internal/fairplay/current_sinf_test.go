package fairplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"testing"
)

type syntheticSINFFixture struct {
	sinf     []byte
	private  []byte
	innerKey [16]byte
	logical  [16]byte
	selector SINFSelector
}

func testAtom(typ string, payload []byte) []byte {
	result := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(result[:4], uint32(len(result)))
	copy(result[4:8], typ)
	copy(result[8:], payload)
	return result
}

func syntheticCurrentSINFFixture(t *testing.T, user, key uint32, righBytes int, innerKey [16]byte) syntheticSINFFixture {
	t.Helper()
	model, err := parseCurrentSINFModel(currentSINFModelPack)
	if err != nil {
		t.Fatal(err)
	}

	types := [...]string{"key ", "iviv", "tmpr", "righ", "name"}
	sizes := [...]int{24, 24, 24, righBytes, 264}
	plaintext := make([]byte, 0, 432)
	for index, typ := range types {
		atom := make([]byte, sizes[index])
		binary.BigEndian.PutUint32(atom[:4], uint32(len(atom)))
		copy(atom[4:8], typ)
		if index == 0 {
			copy(atom[8:], innerKey[:])
		}
		plaintext = append(plaintext, atom...)
	}

	trailerBytes := len(plaintext) % aes.BlockSize
	ciphertextBytes := len(plaintext) - trailerBytes
	iv := [16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	block, err := aes.NewCipher(model.key[:])
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := make([]byte, ciphertextBytes)
	cipher.NewCBCEncrypter(block, iv[:]).CryptBlocks(ciphertext, plaintext[:ciphertextBytes])
	logicalPayload := append(append([]byte(nil), iv[:]...), ciphertext...)
	protected := make([]byte, len(logicalPayload)+trailerBytes)
	for index, value := range logicalPayload {
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
		protected[index] = byte(external) ^ model.whitening[position]
	}

	userPayload := make([]byte, 4)
	keyPayload := make([]byte, 4)
	binary.BigEndian.PutUint32(userPayload, user)
	binary.BigEndian.PutUint32(keyPayload, key)
	fields := append(testAtom("user", userPayload), testAtom("key ", keyPayload)...)
	fields = append(fields, testAtom("priv", protected)...)
	sinf := testAtom("sinf", testAtom("schi", fields))

	return syntheticSINFFixture{
		sinf: sinf, private: protected, innerKey: innerKey,
		logical: logicalFromInnerKey(innerKey), selector: SINFSelector{User: user, Key: key},
	}
}

func TestCurrentSINFModelSyntheticRoundTrip(t *testing.T) {
	model, err := parseCurrentSINFModel(currentSINFModelPack)
	if err != nil {
		t.Fatal(err)
	}
	innerKey := [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}
	fixture := syntheticCurrentSINFFixture(t, 0x10203040, 2, 88, innerKey)
	observed, err := currentSINFPrivateKey(model, fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	if observed != innerKey {
		t.Fatalf("inner key changed: %x", observed)
	}
	gotLogical, _, err := currentSINFLogicalKey(fixture.private)
	if err != nil {
		t.Fatal(err)
	}
	if gotLogical != fixture.logical {
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

func TestCurrentSINFPortableFixtures(t *testing.T) {
	fixtures := []struct {
		name      string
		user, key uint32
		righBytes int
		innerKey  [16]byte
	}{
		{"zero-trailer", 0x10203040, 2, 96, [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10}},
		{"eight-byte-trailer", 0x50607080, 5, 88, [16]byte{0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01}},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			input := syntheticCurrentSINFFixture(t, fixture.user, fixture.key, fixture.righBytes, fixture.innerKey)
			material, resolveErr := ResolveLogicalKey(input.sinf)
			if resolveErr != nil {
				t.Fatal(resolveErr)
			}
			if !bytes.Equal(material.LogicalKey[:], input.logical[:]) {
				t.Fatal("portable current-SINF logical key differs from deterministic fixture")
			}
			if material.Evidence["provider_kind"] != "current-sinf-whitebox-direct-v1" ||
				material.Evidence["runtime_hardware_calls"] != 0 ||
				material.Evidence["request_selector"] != input.selector.Identifier() {
				t.Fatalf("unexpected evidence: %#v", material.Evidence)
			}
		})
	}
}

func TestCurrentSINFRejectsMutation(t *testing.T) {
	fixture := syntheticCurrentSINFFixture(t, 0x90a0b0c0, 7, 96, [16]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99})
	fields, err := parseSINFFields(fixture.sinf)
	if err != nil {
		t.Fatal(err)
	}
	private, err := sinfPrivatePayload(fixture.sinf, fields)
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
