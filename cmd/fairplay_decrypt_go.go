package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/majd/ipatool/v2/internal/fairplay"
	"github.com/spf13/cobra"
)

type fairplayDecryptOptions struct {
	Input  string
	Output string
	Report string
	Force  bool
}

func fairplayDecryptCmd() *cobra.Command {
	var options fairplayDecryptOptions
	cmd := &cobra.Command{
		Use:   "fairplay-decrypt",
		Short: "Decrypt a personalized IPA using the portable FairPlay pipeline",
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := runFairplayDecrypt(cmd.Context(), options)
			if err != nil {
				return err
			}
			dependencies.Logger.Log().
				Str("decryptedOutput", result.OutputPath).
				Str("report", result.ReportPath).
				Bool("success", true).
				Send()
			return nil
		},
	}
	cmd.Flags().StringVar(&options.Input, "input", "", "Personalized encrypted IPA")
	options.addFlags(cmd, "")
	return cmd
}

func (o *fairplayDecryptOptions) addFlags(cmd *cobra.Command, prefix string) {
	cmd.Flags().StringVar(&o.Output, prefix+"output", "", "Decrypted analysis IPA path (defaults beside the input)")
	cmd.Flags().StringVar(&o.Report, prefix+"report", "", "Private decryption report path")
	cmd.Flags().BoolVar(&o.Force, prefix+"force", false, "Replace existing output and report files")
}

func (o fairplayDecryptOptions) normalized() (fairplayDecryptOptions, error) {
	if o.Input == "" {
		return o, errors.New("FairPlay input IPA path is empty")
	}
	if !strings.EqualFold(filepath.Ext(o.Input), ".ipa") {
		return o, errors.New("FairPlay post-processing requires an IPA download")
	}
	stem := strings.TrimSuffix(o.Input, filepath.Ext(o.Input))
	if o.Output == "" {
		o.Output = stem + ".decrypted.ipa"
	}
	if o.Report == "" {
		o.Report = stem + ".decrypted.json"
	}
	return o, nil
}

func runFairplayDecrypt(ctx context.Context, options fairplayDecryptOptions) (fairplay.DecryptResult, error) {
	options, err := options.normalized()
	if err != nil {
		return fairplay.DecryptResult{}, err
	}
	select {
	case <-ctx.Done():
		return fairplay.DecryptResult{}, ctx.Err()
	default:
	}
	return fairplay.DecryptIPA(fairplay.DecryptOptions{
		InputPath:  options.Input,
		OutputPath: options.Output,
		ReportPath: options.Report,
		Force:      options.Force,
	})
}
