package cmd

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("FairPlay options", func() {
	It("uses the embedded current-SINF model", func() {
		options, err := (fairplayDecryptOptions{Input: "App.ipa"}).normalized()
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Output).To(Equal("App.decrypted.ipa"))
		Expect(options.Report).To(Equal("App.decrypted.json"))
		Expect(options.Model).To(BeEmpty())
	})

	It("preserves an explicit enrollment model", func() {
		options, err := (fairplayDecryptOptions{Input: "App.ipa", Model: "profile.bin"}).normalized()
		Expect(err).NotTo(HaveOccurred())
		Expect(options.Model).To(Equal("profile.bin"))
	})
})
