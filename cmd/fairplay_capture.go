package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/majd/ipatool/v2/internal/fairplay"
	"github.com/majd/ipatool/v2/pkg/appstore"
)

type fairPlayCaptureBlobReceipt struct {
	File   string `json:"file"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type fairPlayCaptureSINFReceipt struct {
	fairPlayCaptureBlobReceipt
	Selector string `json:"selector"`
}

type fairPlayCaptureReceipt struct {
	Schema               string                       `json:"schema"`
	Source               string                       `json:"source"`
	AppID                int64                        `json:"app_id"`
	BundleID             string                       `json:"bundle_id,omitempty"`
	ExternalVersionID    string                       `json:"external_version_id,omitempty"`
	Platform             appstore.Platform            `json:"platform,omitempty"`
	DownloadedPackage    string                       `json:"downloaded_package"`
	ContainsCredentials  bool                         `json:"contains_credentials"`
	PersonalizedMaterial bool                         `json:"contains_personalized_material"`
	KBSync               fairPlayCaptureBlobReceipt   `json:"kbsync"`
	Keybag               fairPlayCaptureBlobReceipt   `json:"keybag"`
	SINFs                []fairPlayCaptureSINFReceipt `json:"sinfs"`
}

func writeFairPlayCapture(directory string, out appstore.DownloadOutput, app appstore.App, externalVersionID string, platform appstore.Platform) (result string, err error) {
	if out.FairPlayCapture == nil || len(out.FairPlayCapture.KBSync) == 0 || len(out.FairPlayCapture.Keybag) == 0 {
		return "", errors.New("download returned no paired FairPlay KBSync/keybag capture")
	}
	if len(out.Sinfs) == 0 {
		return "", errors.New("download returned no SINF for the FairPlay capture")
	}

	absolute, err := filepath.Abs(directory)
	if err != nil {
		return "", fmt.Errorf("resolve FairPlay capture directory: %w", err)
	}
	parent := filepath.Dir(absolute)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return "", fmt.Errorf("create FairPlay capture parent: %w", err)
	}
	if err := os.Mkdir(absolute, 0700); err != nil {
		return "", fmt.Errorf("create new FairPlay capture directory: %w", err)
	}

	complete := false
	defer func() {
		if !complete {
			if cleanupErr := os.RemoveAll(absolute); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("remove incomplete FairPlay capture: %w", cleanupErr))
			}
		}
	}()

	receipt := fairPlayCaptureReceipt{
		Schema:               "ipatool-fairplay-enrollment-capture-v1",
		Source:               "ent/download",
		AppID:                app.ID,
		BundleID:             app.BundleID,
		ExternalVersionID:    externalVersionID,
		Platform:             platform,
		DownloadedPackage:    filepath.Base(out.DestinationPath),
		ContainsCredentials:  false,
		PersonalizedMaterial: true,
	}

	receipt.KBSync, err = writeFairPlayCaptureBlob(absolute, "kbsync.bin", out.FairPlayCapture.KBSync)
	if err != nil {
		return "", err
	}
	receipt.Keybag, err = writeFairPlayCaptureBlob(absolute, "keybag.bin", out.FairPlayCapture.Keybag)
	if err != nil {
		return "", err
	}

	for index, item := range out.Sinfs {
		if len(item.Data) == 0 {
			return "", fmt.Errorf("FairPlay capture SINF %d is empty", index)
		}
		name := "sinf.bin"
		if len(out.Sinfs) != 1 {
			name = fmt.Sprintf("sinf-%02d.bin", index)
		}
		blob, writeErr := writeFairPlayCaptureBlob(absolute, name, item.Data)
		if writeErr != nil {
			return "", writeErr
		}
		selector, selectorErr := fairplay.ParseSINFSelector(item.Data)
		if selectorErr != nil {
			return "", fmt.Errorf("parse captured SINF %d selector: %w", index, selectorErr)
		}
		receipt.SINFs = append(receipt.SINFs, fairPlayCaptureSINFReceipt{
			fairPlayCaptureBlobReceipt: blob,
			Selector:                   selector.Identifier(),
		})
	}

	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode FairPlay capture receipt: %w", err)
	}
	encoded = append(encoded, '\n')
	if _, err := writeFairPlayCaptureBlob(absolute, "receipt.json", encoded); err != nil {
		return "", err
	}

	complete = true
	return absolute, nil
}

func writeFairPlayCaptureBlob(directory, name string, data []byte) (receipt fairPlayCaptureBlobReceipt, err error) {
	path := filepath.Join(directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return receipt, fmt.Errorf("create private FairPlay capture file %s: %w", name, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("close FairPlay capture file %s: %w", name, closeErr))
		}
	}()

	if _, err := file.Write(data); err != nil {
		return receipt, fmt.Errorf("write FairPlay capture file %s: %w", name, err)
	}
	digest := sha256.Sum256(data)

	return fairPlayCaptureBlobReceipt{
		File:   name,
		Bytes:  len(data),
		SHA256: hex.EncodeToString(digest[:]),
	}, nil
}
