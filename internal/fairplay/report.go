package fairplay

type imageReport struct {
	Member                         string               `json:"member"`
	SUPFMember                     string               `json:"supf_member"`
	Architecture                   string               `json:"architecture"`
	CPUType                        uint32               `json:"cpu_type"`
	CPUSubtype                     uint32               `json:"cpu_subtype"`
	SliceOffset                    uint64               `json:"slice_offset"`
	SliceSize                      uint64               `json:"slice_size"`
	EncryptedSHA256                string               `json:"encrypted_sha256"`
	DecryptedSHA256                string               `json:"decrypted_sha256"`
	CryptOffset                    uint32               `json:"cryptoff"`
	CryptSize                      uint32               `json:"cryptsize"`
	Pages                          int                  `json:"pages"`
	FirstPlaintextPageSHA256       string               `json:"first_plaintext_page_sha256"`
	FirstPageAudit                 string               `json:"first_page_audit"`
	FirstPageValidARM64Words       int                  `json:"first_page_valid_arm64_words,omitempty"`
	FirstPageInstructionWords      int                  `json:"first_page_instruction_words,omitempty"`
	FirstPageStructurallyPlausible bool                 `json:"first_page_structurally_plausible"`
	FirstPageMnemonics             map[string]int       `json:"first_page_mnemonics"`
	OrderedPageKeysSHA256          string               `json:"ordered_page_keys_sha256"`
	AppMaskSHA256                  string               `json:"app_mask_sha256"`
	CodeDirectories                []codeDirectoryAudit `json:"code_directories"`
	CryptIDBefore                  uint32               `json:"cryptid_before"`
	CryptIDAfter                   uint32               `json:"cryptid_after"`
	ExactMutationScope             bool                 `json:"exact_mutation_scope"`
}

type reportFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes,omitempty"`
	Mode   string `json:"mode,omitempty"`
}

type decryptionReport struct {
	Schema            string         `json:"schema"`
	ModelBuild        string         `json:"model_build"`
	Input             reportFile     `json:"input"`
	Output            reportFile     `json:"output"`
	Provider          string         `json:"provider"`
	Oracle            map[string]any `json:"oracle"`
	EncryptedImages   int            `json:"encrypted_image_count"`
	DecryptedPages    int            `json:"decrypted_page_count"`
	Images            []*imageReport `json:"images"`
	Complete          bool           `json:"complete"`
	PlaintextVerified bool           `json:"plaintext_verified"`
	SignatureVerified bool           `json:"signature_verified"`
	Warnings          []string       `json:"warnings"`
}
