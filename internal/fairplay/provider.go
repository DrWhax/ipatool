package fairplay

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type KeyMaterial struct {
	LogicalKey [16]byte
	Evidence   map[string]any
}

func digest(blob []byte) string {
	value := sha256.Sum256(blob)
	return hex.EncodeToString(value[:])
}

func ResolveLogicalKey(sinf []byte) (KeyMaterial, error) {
	model, err := parseEmbeddedCurrentSINFModel()
	if err != nil {
		return KeyMaterial{}, err
	}
	return resolveLogicalKey(sinf, model, currentSINFModelName, currentSINFModelSHA256, "embedded-build-specific-current-sinf-model")
}

// ResolveLogicalKeyWithModel resolves a SINF with an enrollment model produced
// by a matching provisioning run. Model packs are intentionally data, not Go
// code, so the decryption path remains portable after enrollment.
func ResolveLogicalKeyWithModel(sinf, pack []byte) (KeyMaterial, error) {
	model, err := parseCurrentSINFModel(pack)
	if err != nil {
		return KeyMaterial{}, err
	}
	modelSHA256 := digest(pack)
	modelName := "external-current-sinf-" + modelSHA256[:16]
	return resolveLogicalKey(sinf, model, modelName, modelSHA256, "external-enrollment-model")
}

func resolveLogicalKey(sinf []byte, model currentSINFModel, modelName, modelSHA256, stateOrigin string) (KeyMaterial, error) {
	var result KeyMaterial
	fields, err := parseSINFFields(sinf)
	if err != nil {
		return result, err
	}
	selector, err := sinfSelector(sinf, fields)
	if err != nil {
		return result, err
	}
	private, err := sinfPrivatePayload(sinf, fields)
	if err != nil {
		return result, err
	}
	innerKey, err := currentSINFPrivateKey(model, private)
	if err != nil {
		return result, fmt.Errorf("unsupported FairPlay enrollment %s: %w", selector.Identifier(), err)
	}
	defer clear(innerKey[:])
	logical := logicalFromInnerKey(innerKey)
	result.LogicalKey = logical
	result.Evidence = map[string]any{
		"provider_kind":          "current-sinf-whitebox-direct-v1",
		"provider_status":        0,
		"selector_status":        0,
		"status_patched":         false,
		"device_state_imported":  false,
		"state_origin":           stateOrigin,
		"hardware_backend":       "none",
		"runtime_hardware_calls": 0,
		"request_selector":       selector.Identifier(),
		"model_name":             modelName,
		"model_sha256":           modelSHA256,
		"fairplayd_sha256":       hex.EncodeToString(model.fairplaydHash[:]),
		"logical_key_sha256":     digest(logical[:]),
	}
	return result, nil
}
