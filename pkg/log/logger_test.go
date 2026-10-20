package log

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/rs/zerolog"
)

var _ = Describe("Logger", func() {
	var (
		logWriter *recordingLogWriter
		logger    Logger
	)

	BeforeEach(func() {
		logWriter = &recordingLogWriter{}
	})

	Context("Verbose logger", func() {
		BeforeEach(func() {
			logger = NewLogger(Args{
				Verbose: true,
				Writer:  logWriter,
			})
		})

		When("logging with verbose level", func() {
			It("writes output", func() {
				logger.Verbose().Msg("verbose")
				Expect(logWriter.level).To(Equal(zerolog.DebugLevel))
				Expect(logWriter.payload).To(ContainSubstring("\"message\":\"verbose\""))
			})
		})
	})

	Context("Non-verbose logger", func() {
		BeforeEach(func() {
			logger = NewLogger(Args{
				Verbose: false,
				Writer:  logWriter,
			})
		})

		When("logging messsage", func() {
			It("writes output", func() {
				logger.Log().Msg("info")
				Expect(logWriter.level).To(Equal(zerolog.InfoLevel))
				Expect(logWriter.payload).To(ContainSubstring("\"message\":\"info\""))
			})
		})

		When("logging error", func() {
			It("writes output", func() {
				logger.Error().Msg("error")
				Expect(logWriter.level).To(Equal(zerolog.ErrorLevel))
				Expect(logWriter.payload).To(ContainSubstring("\"message\":\"error\""))
			})
		})

		When("logging with verbose level", func() {
			It("returns nil", func() {
				res := logger.Verbose()
				Expect(res).To(BeNil())
			})
		})
	})
})

type recordingLogWriter struct {
	level   zerolog.Level
	payload string
}

func (w *recordingLogWriter) Write(p []byte) (int, error) {
	w.payload = string(p)
	return len(p), nil
}

func (w *recordingLogWriter) WriteLevel(level zerolog.Level, p []byte) (int, error) {
	w.level = level
	w.payload = string(p)
	return len(p), nil
}
