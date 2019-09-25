package crypto

type Cryptor interface {
	Encrypt(plaintext []byte) (string, error)
	Decrypt(encrypted []byte) ([]byte, error)
}
