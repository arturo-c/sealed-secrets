package crypto

type Cryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(encrypted []byte) ([]byte, error)
}
