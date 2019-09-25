package crypto

import (
	"context"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault/seal/transit"
)

type Vault struct {
	Cryptor
	Address   string
	Token     string
	KeyName   string
	MountPath string
}

func (c Vault) Encrypt(d []byte) ([]byte, error) {
	s := transit.NewSeal(logging.NewVaultLogger(log.Trace))
	config := map[string]string{
		"address":    c.Address,
		"key_name":   c.KeyName,
		"token":      c.Token,
		"mount_path": c.MountPath,
	}
	s.SetConfig(config)

	swi, err := s.Encrypt(context.Background(), d)
	if err != nil {
		return []byte{}, err
	}
	return swi.GetCiphertext(), nil
}

func (c Vault) Decrypt(e []byte) ([]byte, error) {
	s := transit.NewSeal(logging.NewVaultLogger(log.Trace))
	config := map[string]string{
		"address":    c.Address,
		"key_name":   c.KeyName,
		"token":      c.Token,
		"mount_path": c.MountPath,
	}
	s.SetConfig(config)

	data := &physical.EncryptedBlobInfo{
		Ciphertext: e,
	}
	return s.Decrypt(context.Background(), data)
}
