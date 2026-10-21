package appstore

import "encoding/base64"

func cloneFairPlayDownloadCapture(source *FairPlayDownloadCapture) *FairPlayDownloadCapture {
	if source == nil {
		return nil
	}

	return &FairPlayDownloadCapture{
		KBSync: append([]byte(nil), source.KBSync...),
		Keybag: append([]byte(nil), source.Keybag...),
	}
}

func downloadResponseKeybag(response downloadResult) []byte {
	values := []interface{}{response.Keybag, response.SubKeyBag, response.SBKeyBag}
	for _, item := range response.Items {
		values = append(values, item.Keybag, item.SubKeyBag, item.SBKeyBag)
		for _, key := range []string{"keybag", "subKeyBag", "sbKeyBag"} {
			values = append(values, item.Metadata[key])
		}
	}

	for _, value := range values {
		data := downloadResponseBlob(value)
		if len(data) != 0 {
			return data
		}
	}

	return nil
}

func downloadResponseBlob(value interface{}) []byte {
	switch typed := value.(type) {
	case []byte:
		return append([]byte(nil), typed...)
	case string:
		decoded, err := base64.StdEncoding.DecodeString(typed)
		if err == nil {
			return decoded
		}
	}

	return nil
}
