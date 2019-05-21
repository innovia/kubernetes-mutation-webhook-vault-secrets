// This script expect basic vault env vars to exist before execution
// a new set of env vars (sanitizedEnviron) is then made to hole only the env appears in the secret

package main

import (
	"fmt"
	"github.com/innovia/vault-env/vault"
	log "github.com/sirupsen/logrus"
	"os"
	"os/exec"
	"strings"
	"syscall"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/spf13/cast"
)

type sanitizedEnviron []string

var sanitizeEnvmap = map[string]bool{
	"VAULT_TOKEN":           true,
	"VAULT_ADDR":            true,
	"VAULT_CACERT":          true,
	"VAULT_CAPATH":          true,
	"VAULT_CLIENT_CERT":     true,
	"VAULT_CLIENT_KEY":      true,
	"VAULT_CLIENT_TIMEOUT":  true,
	"VAULT_CLUSTER_ADDR":    true,
	"VAULT_MAX_RETRIES":     true,
	"VAULT_REDIRECT_ADDR":   true,
	"VAULT_SKIP_VERIFY":     true,
	"VAULT_TLS_SERVER_NAME": true,
	"VAULT_CLI_NO_COLOR":    true,
	"VAULT_RATE_LIMIT":      true,
	"VAULT_NAMESPACE":       true,
	"VAULT_MFA":             true,
	"VAULT_ROLE":            true,
	"VAULT_PATH":            true,
}

// Appends variable an entry (name=value) into the environ list.
// VAULT_* variables are not populated into this list.
func (environ *sanitizedEnviron) append(iname interface{}, ivalue interface{}) {
	name, value := iname.(string), ivalue.(string)
	if _, ok := sanitizeEnvmap[name]; !ok {
		*environ = append(*environ, fmt.Sprintf("%s=%s", name, value))
	}
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
	})

	role := os.Getenv("VAULT_ROLE")
	path := os.Getenv("VAULT_PATH")

	if role == "" {
		log.Fatal("VAULT_ROLE environment variables is missing")
	}

	if path == "" {
		log.Fatal("VAULT_PATH environment variables is missing")
	}

	log.Infof("Logging into Vault Kubernetes backend using the role: %s", role)
	client, err := vault.NewClientWithConfig(vaultapi.DefaultConfig(), role)

	if err != nil {
		log.Fatalf("Failed to create vault client: %s", err.Error())
	}

	// initial and sanitized environs
	environ := syscall.Environ()
	sanitized := make(sanitizedEnviron, 0, len(environ))

	// fetch the secrets from path
	var secret *vaultapi.Secret
	var secretError error
	log.Infof("Getting Vault secrets from path: %s", path)
	secret, secretError = client.Logical.Read(path)
	if secretError != nil {
		log.Fatalf("Failed to read secret '%s': %s", path, err.Error())
	}
	if secret == nil {
		log.Fatalf("Vault secret path not found: %s", path)
	}

	log.Info("Processing environment variables from Vault secret")
	for _, env := range environ {
		split := strings.SplitN(env, "=", 2)
		name := split[0]
		value := split[1]

		if strings.HasPrefix(value, "vault:") {
			key := strings.TrimPrefix(value, "vault:")
			var data map[string]interface{}
			v2Data, ok := secret.Data["data"]
			if ok {
				data = cast.ToStringMap(v2Data)
			} else {
				data = cast.ToStringMap(secret.Data)
			}
			if value, ok := data[key]; ok {
				sanitized.append(name, value)
			} else {
				fmt.Fprintf(os.Stderr, "key not found: %s", key)
				os.Exit(1)
			}
		} else {
			sanitized.append(name, value)
		}

	}
	log.Info("Launching command")
	if len(os.Args) == 1 {
		log.Fatal(
			"No command is given, currently vault-env can't determine the entrypoint (command) ",
			"please specify it explicitly",
		)
	} else {
		binary, err := exec.LookPath(os.Args[1])
		if err != nil {
			log.Fatalf("Binary not found: %s", os.Args[1])
		}
		log.Debugf("Running command using execv: %s %s", binary, os.Args[1:])
		log.Debugf("Sanitized env: %s", sanitized)
		err = syscall.Exec(binary, os.Args[1:], sanitized)
		if err != nil {
			log.Fatalf("Failed to exec process '%s': %s", binary, err.Error())
		}
	}
}
