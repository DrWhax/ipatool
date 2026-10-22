package fairplay

import (
	"crypto/aes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	currentSINFModelName      = "macos27.0.1-26A428-current-sinf"
	currentSINFSupportedBuild = "macOS 27.0.1 (26A428)"
	currentSINFModelSHA256    = "c9b7c4885f8ca634ee73e4b20de610a0d6d2e7d56336358733526ceca8f2e5bb"
	currentSINFModelBytes     = 8 + 4 + 4 + 32 + 16 + 16 + 16*256
	legacySINFModelMagic      = "FPS26A4\x00"
	enrollmentModelMagic      = "FPSENR1\x00"
)

var errCurrentSINFProfileMismatch = errors.New("SINF does not match the selected FairPlay model")

//go:embed models/macos26-26A428-current-sinf.bin
var currentSINFModelPack []byte

type currentSINFModel struct {
	fairplaydHash [32]byte
	key           [16]byte
	whitening     [16]byte
	inputDecode   [16 * 256]byte
}

func parseCurrentSINFModel(pack []byte) (currentSINFModel, error) {
	var model currentSINFModel
	if len(pack) != currentSINFModelBytes ||
		(string(pack[:8]) != legacySINFModelMagic && string(pack[:8]) != enrollmentModelMagic) ||
		binary.LittleEndian.Uint32(pack[8:12]) != 1 ||
		binary.LittleEndian.Uint32(pack[12:16]) != uint32(len(pack)) {
		return model, fmt.Errorf("invalid current SINF model envelope")
	}
	copy(model.fairplaydHash[:], pack[16:48])
	copy(model.key[:], pack[48:64])
	copy(model.whitening[:], pack[64:80])
	copy(model.inputDecode[:], pack[80:])
	for position := 0; position < 16; position++ {
		var seen [256]bool
		for _, value := range model.inputDecode[position*256 : (position+1)*256] {
			if seen[value] {
				return currentSINFModel{}, fmt.Errorf("current SINF input table %d is not a permutation", position)
			}
			seen[value] = true
		}
	}
	return model, nil
}

func parseEmbeddedCurrentSINFModel() (currentSINFModel, error) {
	return parseCurrentSINFModelWithDigest(currentSINFModelPack, currentSINFModelSHA256)
}

func parseCurrentSINFModelWithDigest(pack []byte, expected string) (currentSINFModel, error) {
	if digest(pack) != expected {
		return currentSINFModel{}, fmt.Errorf("invalid embedded current SINF model")
	}
	return parseCurrentSINFModel(pack)
}

func currentSINFPrivateKey(model currentSINFModel, source []byte) ([16]byte, error) {
	var innerKey [16]byte
	if len(source) < 48 {
		return innerKey, fmt.Errorf("%w: priv source is too short", errCurrentSINFProfileMismatch)
	}
	bodyBytes := len(source) - aes.BlockSize
	trailerBytes := bodyBytes % aes.BlockSize
	ciphertextBytes := bodyBytes - trailerBytes
	if ciphertextBytes < 2*aes.BlockSize || trailerBytes != 0 && trailerBytes != 8 {
		return innerKey, fmt.Errorf("%w: priv block geometry is invalid", errCurrentSINFProfileMismatch)
	}
	encodedBytes := aes.BlockSize + ciphertextBytes
	trailer := source[encodedBytes:]
	for _, value := range trailer {
		if value != 0 {
			return innerKey, fmt.Errorf("%w: priv trailer is not zero", errCurrentSINFProfileMismatch)
		}
	}

	logical := make([]byte, encodedBytes)
	plaintext := []byte(nil)
	decrypted := []byte(nil)
	defer func() {
		clear(logical)
		clear(plaintext)
		clear(decrypted)
	}()
	for index, value := range source[:encodedBytes] {
		position := index % aes.BlockSize
		external := value ^ model.whitening[position]
		logical[index] = model.inputDecode[position*256+int(external)]
	}
	var err error
	decrypted, err = aesCBCDecrypt(logical[aes.BlockSize:], model.key[:], logical[:aes.BlockSize])
	if err != nil {
		return innerKey, fmt.Errorf("decode embedded current SINF model: %w", err)
	}
	plaintext = make([]byte, len(decrypted)+len(trailer))
	copy(plaintext, decrypted)
	copy(plaintext[len(decrypted):], trailer)

	expectedAtoms := [...]struct {
		typ   string
		sizes []int
	}{
		{"key ", []int{24}},
		{"iviv", []int{24}},
		{"tmpr", []int{24}},
		{"righ", []int{88, 96}},
		{"name", []int{264}},
	}
	cursor := 0
	for index, expected := range expectedAtoms {
		atom, parseErr := parseClearAtom(plaintext, cursor, len(plaintext))
		if parseErr != nil {
			return innerKey, fmt.Errorf("%w: plaintext atom %d: %v", errCurrentSINFProfileMismatch, index, parseErr)
		}
		validSize := false
		for _, size := range expected.sizes {
			validSize = validSize || atom.end-cursor == size
		}
		if atom.typ != expected.typ || !validSize {
			return innerKey, fmt.Errorf("%w: plaintext has invalid %s atom", errCurrentSINFProfileMismatch, expected.typ)
		}
		if index == 0 {
			copy(innerKey[:], plaintext[cursor+8:atom.end])
		}
		cursor = atom.end
	}
	if cursor != len(plaintext) {
		return innerKey, fmt.Errorf("%w: plaintext has trailing data", errCurrentSINFProfileMismatch)
	}
	return innerKey, nil
}
