package vault

import (
	vaultapi "github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
)

const (
	serviceAccountFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

type vaultConfig struct {
	addr       string
	role       string
	skipVerify string
}

// Client is a Vault client with Kubernetes support
type Client struct {
	Client  *vaultapi.Client
	Logical *vaultapi.Logical
}

// GetServiceAccountToken read Kubernetes service account token
func GetServiceAccountToken() ([]byte, error) {
	log.Info("Getting Service Account Token")
	jwt, err := ioutil.ReadFile(serviceAccountFile)
	if err != nil {
		log.Errorf("Failed to read service acccount token file: %s", err.Error())
		return nil, err
	}
	return jwt, nil
}

// GetVaultClientToken Authenticate to Vault
func GetVaultClientToken(client *Client, role string, jwt []byte) (string, error) {
	params := map[string]interface{}{"jwt": string(jwt), "role": role}
	secretData, err := client.Logical.Write("auth/kubernetes/login", params)
	if err != nil {
		log.Errorf("Failed to request new Vault token", err.Error())
		return "", err
	}
	clientToken := &secretData.Auth.ClientToken
	return *clientToken, nil
}

// NewClient new vault client
func NewClient(role string) (*Client, error) {
	return NewClientWithConfig(vaultapi.DefaultConfig(), role)
}

// NewClientWithConfig create a new vault client
func NewClientWithConfig(config *vaultapi.Config, role string) (*Client, error) {
	rawClient, err := vaultapi.NewClient(config)
	if err != nil {
		return nil, err
	}
	logical := rawClient.Logical()
	client := &Client{Client: rawClient, Logical: logical}

	jwt, err := GetServiceAccountToken()
	if err != nil {
		return nil, err
	}

	clientToken, err := GetVaultClientToken(client, role, jwt)

	if err == nil {
		rawClient.SetToken(string(clientToken))
	} else {
		return nil, err
	}
	return client, nil
	// caCertPath := os.Getenv(vaultapi.EnvVaultCACert)
}
