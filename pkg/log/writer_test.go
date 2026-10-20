package log

import (
	"bytes"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/rs/zerolog"
)

var _ = Describe("Writer", func() {
	var (
		stdout bytes.Buffer
		stderr bytes.Buffer
		sut    *writer
	)

	BeforeEach(func() {
		stdout.Reset()
		stderr.Reset()
		sut = &writer{
			stdOutWriter: &stdout,
			stdErrWriter: &stderr,
		}
	})

	It("returns valid writer", func() {
		out := NewWriter()
		Expect(out).ToNot(BeNil())
	})

	When("writing logs", func() {
		It("writes debug logs to stdout", func() {
			_, err := sut.WriteLevel(zerolog.DebugLevel, []byte("debug"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stdout.String()).To(Equal("debug"))
		})

		It("writes info logs to stdout", func() {
			_, err := sut.Write([]byte("info"))
			Expect(err).ToNot(HaveOccurred())

			_, err = sut.WriteLevel(zerolog.InfoLevel, []byte("info"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stdout.String()).To(Equal("infoinfo"))
		})

		It("writes warn logs to stdout", func() {
			_, err := sut.WriteLevel(zerolog.WarnLevel, []byte("warning"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stdout.String()).To(Equal("warning"))
		})

		It("writes error logs to stderr", func() {
			_, err := sut.WriteLevel(zerolog.ErrorLevel, []byte("error"))
			Expect(err).ToNot(HaveOccurred())
			Expect(stderr.String()).To(Equal("error"))
		})
	})

	When("log level is not supported", func() {
		It("returns the length of the passed log", func() {
			length, err := sut.WriteLevel(zerolog.PanicLevel, []byte("panic"))
			Expect(err).ToNot(HaveOccurred())
			Expect(length).To(Equal(5))
		})
	})
})
