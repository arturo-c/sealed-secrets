package vault

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/physical"
	"github.com/hashicorp/vault/vault/seal/transit"
)

var (
	// ErrMissingVaultKubernetesPath is our error, if the mount path of the Kubernetes Auth Method is not provided.
	ErrMissingVaultKubernetesPath = errors.New("missing ttl for vault token")
	// ErrMissingVaultKubernetesRole is our error, if the role for the Kubernetes Auth Method is not provided.
	ErrMissingVaultKubernetesRole = errors.New("missing ttl for vault token")
	// ErrMissingVaultAuthInfo is our error, if sth. went wrong during the authentication agains Vault.
	ErrMissingVaultAuthInfo = errors.New("missing authentication information")

	// log is our customized logger.
	logger = logging.NewVaultLogger(log.Trace)

	// client is the API client for the interaction with the Vault API.
	client *api.Client

	// tokenLeaseDuration is the lease duration of the token for the interaction with vault.
	tokenLeaseDuration = 1800

	// vault vals
	vaultAddress        = getEnv("VAULT_ADDRESS", "http://localhost:8200")
	vaultKubernetesPath = getEnv("VAULT_KUBERNETES_PATH", "kubernetes")
	vaultKubernetesRole = getEnv("VAULT_KUBERNETES_ROLE", "default")
	vaultTransitKey     = getEnv("VAULT_TRANSIT_KEY", "sealed-secrets")
	vaultTransitPath    = getEnv("VAULT_TRANSIT_PATH", "transit")
)

// CreateClient creates a new Vault API client.
func CreateClient() error {
	var err error
	vaultToken := os.Getenv("VAULT_TOKEN")

	config := &api.Config{
		Address: vaultAddress,
		HttpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}

	client, err = api.NewClient(config)
	if err != nil {
		return err
	}

	// Check which authentication method should be used.
	if vaultToken != "" {
		// Set the token, which should be used for the interaction with Vault.
		client.SetToken(vaultToken)
	} else {
		// Check the required mount path and role for the Kubernetes Auth
		// Method. If one of the env variable is missing we return an error.
		if vaultKubernetesPath == "" {
			return ErrMissingVaultKubernetesPath
		}

		if vaultKubernetesRole == "" {
			return ErrMissingVaultKubernetesRole
		}

		// Read the service account token value and create a map for the
		// authentication against Vault.
		kubeToken, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
		if err != nil {
			return err
		}

		data := make(map[string]interface{})
		data["jwt"] = string(kubeToken)
		data["role"] = vaultKubernetesRole

		// Authenticate against vault using the Kubernetes Auth Method and set
		// the token which the client should use for further interactions with
		// Vault. We also set the lease duration of the token for the renew
		// function.
		secret, err := client.Logical().Write(vaultKubernetesPath+"/login", data)
		if err != nil {
			return err
		} else if secret.Auth == nil {
			return ErrMissingVaultAuthInfo
		}

		tokenLeaseDuration = secret.Auth.LeaseDuration
		client.SetToken(secret.Auth.ClientToken)
	}

	return nil
}

// RenewToken renews the provided token after the half of the lease duration is
// passed.
func RenewToken() {
	for {
		logger.Info("Renew Vault token")

		_, err := client.Auth().Token().RenewSelf(tokenLeaseDuration)
		if err != nil {
			logger.Error("Could not renew token: %s", err.Error())
		}

		time.Sleep(time.Duration(float64(tokenLeaseDuration)*0.5) * time.Second)
	}
}

func Encrypt(d []byte) ([]byte, error) {
	s := transit.NewSeal(logger)
	config := map[string]string{
		"address":    client.Address(),
		"key_name":   vaultTransitKey,
		"token":      client.Token(),
		"mount_path": vaultTransitPath,
	}
	s.SetConfig(config)

	swi, err := s.Encrypt(context.Background(), d)
	if err != nil {
		return []byte{}, err
	}
	return swi.GetCiphertext(), nil
}

func Decrypt(e []byte) ([]byte, error) {
	s := transit.NewSeal(logger)
	config := map[string]string{
		"address":    client.Address(),
		"key_name":   vaultTransitKey,
		"token":      client.Token(),
		"mount_path": vaultTransitPath,
	}
	s.SetConfig(config)

	data := &physical.EncryptedBlobInfo{
		Ciphertext: e,
	}
	return s.Decrypt(context.Background(), data)
}

// contains checks if a given key is in a slice of keys.
func contains(key string, keys []string) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}

	return false
}

// getEnv looksup key, fallback on 2nd param.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
