package appstore

import (
	"encoding/base64"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FairPlay download response capture", func() {
	It("accepts a top-level binary keybag", func() {
		response := downloadResult{Keybag: []byte("top-level")}
		Expect(downloadResponseKeybag(response)).To(Equal([]byte("top-level")))
	})

	It("accepts a base64 item metadata keybag", func() {
		response := downloadResult{Items: []downloadItemResult{{
			Metadata: map[string]interface{}{
				"keybag": base64.StdEncoding.EncodeToString([]byte("metadata")),
			},
		}}}
		Expect(downloadResponseKeybag(response)).To(Equal([]byte("metadata")))
	})

	It("ignores malformed or absent values", func() {
		response := downloadResult{Items: []downloadItemResult{{
			Metadata: map[string]interface{}{"keybag": "not base64"},
		}}}
		Expect(downloadResponseKeybag(response)).To(BeNil())
	})

	It("clones both sensitive buffers", func() {
		source := &FairPlayDownloadCapture{KBSync: []byte("request"), Keybag: []byte("response")}
		cloned := cloneFairPlayDownloadCapture(source)
		Expect(cloned).To(Equal(source))
		cloned.KBSync[0] ^= 0xff
		cloned.Keybag[0] ^= 0xff
		Expect(cloned.KBSync).NotTo(Equal(source.KBSync))
		Expect(cloned.Keybag).NotTo(Equal(source.Keybag))
	})
})
