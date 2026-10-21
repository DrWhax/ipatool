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
	logical, model, err := currentSINFLogicalKey(private)
	if err != nil {
		return result, fmt.Errorf("unsupported FairPlay enrollment %s: %w", selector.Identifier(), err)
	}
	result.LogicalKey = logical
	result.Evidence = map[string]any{
		"provider_kind":          "current-sinf-whitebox-direct-v1",
		"provider_status":        0,
		"selector_status":        0,
		"status_patched":         false,
		"device_state_imported":  false,
		"state_origin":           "embedded-build-specific-current-sinf-model",
		"hardware_backend":       "none",
		"runtime_hardware_calls": 0,
		"request_selector":       selector.Identifier(),
		"model_name":             currentSINFModelName,
		"model_sha256":           currentSINFModelSHA256,
		"fairplayd_sha256":       hex.EncodeToString(model.fairplaydHash[:]),
		"logical_key_sha256":     digest(logical[:]),
	}
	return result, nil
}
