package crypto

type Cryptor interface {
	Encrypt(EncryptData) ([]byte, error)
	Decrypt(DecryptData) ([]byte, error)
}

type EncryptData struct {
	CertConfig  CertConfig
	VaultConfig VaultConfig
	Plaintext   []byte
}

type DecryptData struct {
	CertConfig    CertConfig
	VaultConfig   VaultConfig
	EncryptedText []byte
}
