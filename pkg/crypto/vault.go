package crypto

import (
	"context"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/vault/seal/transit"
)

type VaultEncrypt struct {
	Cryptor
}

type VaultConfig struct {
	Address   string
	Token     string
	KeyName   string
	MountPath string
}

func (c VaultEncrypt) Encrypt(d EncryptData) ([]byte, error) {
	s := transit.NewSeal(logging.NewVaultLogger(log.Trace))
	config := map[string]string{
		"address":    d.VaultConfig.Address,
		"key_name":   d.VaultConfig.KeyName,
		"token":      d.VaultConfig.Token,
		"mount_path": d.VaultConfig.MountPath,
	}
	s.SetConfig(config)

	swi, err := s.Encrypt(context.Background(), d.Plaintext)
	if err != nil {
		return []byte{}, err
	}
	return swi.Ciphertext, nil
}
