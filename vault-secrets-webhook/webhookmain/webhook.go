// https://banzaicloud.com/blog/slok-webhook/
package webhookmain

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	whhttp "github.com/slok/kubewebhook/pkg/http"
	"github.com/slok/kubewebhook/pkg/log"
	whcontext "github.com/slok/kubewebhook/pkg/webhook/context"
	"github.com/slok/kubewebhook/pkg/webhook/mutating"

	"github.com/spf13/viper"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// VaultConfig type
type VaultConfig struct {
	Addr          string
	Role          string
	Path          string
	Enabled       bool
	TLSSecretName string
}

// Kubernetes client set
func newClientSet() (*kubernetes.Clientset, error) {
	kubeconfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}

func getVolumes(vaultConfig VaultConfig) []corev1.Volume {
	volumes := []corev1.Volume{
		{
			Name: "vault-env",
			VolumeSource: corev1.VolumeSource{
				EmptyDir: &corev1.EmptyDirVolumeSource{
					Medium: corev1.StorageMediumMemory,
				},
			},
		}, {
			Name: "tls",
			VolumeSource: corev1.VolumeSource{
				Secret: &corev1.SecretVolumeSource{
					SecretName: vaultConfig.TLSSecretName,
				},
			},
		},
	}
	return volumes
}

func getInitContainers(vaultConfig VaultConfig) []corev1.Container {
	containers := []corev1.Container{}

	containers = append(containers, corev1.Container{
		Name:            "init",
		Image:           viper.GetString("vault_env_image"),
		ImagePullPolicy: corev1.PullIfNotPresent,
		Command:         []string{"sh", "-c", "cp /usr/local/bin/vault-env /vault/"},
		VolumeMounts: []corev1.VolumeMount{
			{
				Name:      "vault-env",
				MountPath: "/vault",
			},
		},
	})
	return containers
}

func mutateContainers(containers []corev1.Container, vaultConfig VaultConfig, ns string) (bool, error) {
	mutated := false
	for i, container := range containers {
		var envVars []corev1.EnvVar

		for _, env := range container.Env {
			if strings.HasPrefix(env.Value, "vault:") {
				envVars = append(envVars, env)
			}
		}

		if len(envVars) == 0 {
			continue
		}

		mutated = true

		// add args to command list; cmd arg arg
		args := append(container.Command, container.Args...)

		container.Command = []string{"/vault/vault-env"}
		container.Args = args

		// add the volume mount for vault-env
		container.VolumeMounts = append(container.VolumeMounts, []corev1.VolumeMount{
			{
				Name:      "vault-env",
				MountPath: "/vault",
			}, {
				Name:      "tls",
				MountPath: "/etc/tls",
			},
		}...)

		// transform pod annotations to env vars for vault-env execution
		container.Env = append(container.Env, []corev1.EnvVar{
			{
				Name:  "VAULT_ADDR",
				Value: vaultConfig.Addr,
			},
			{
				Name:  "VAULT_PATH",
				Value: vaultConfig.Path,
			},
			{
				Name:  "VAULT_ROLE",
				Value: vaultConfig.Role,
			}, {
				Name:  "VAULT_CAPATH",
				Value: "/etc/tls/ca.pem",
			},
		}...)

		containers[i] = container
	}
	return mutated, nil
}

// MutatePodSpec mutate the given pod spec
func MutatePodSpec(obj metav1.Object, podSpec *corev1.PodSpec, vaultConfig VaultConfig, ns string) error {
	fmt.Println("starting mutation chain for pod spec")
	initContainersMutated, err := mutateContainers(podSpec.InitContainers, vaultConfig, ns)
	if err != nil {
		return err
	}

	containersMutated, err := mutateContainers(podSpec.Containers, vaultConfig, ns)
	if err != nil {
		return err
	}

	if initContainersMutated || containersMutated {
		podSpec.InitContainers = append(getInitContainers(vaultConfig), podSpec.InitContainers...)
		podSpec.Volumes = append(podSpec.Volumes, getVolumes(vaultConfig)...)
	}

	return nil
}

func parseVaultConfig(obj metav1.Object) VaultConfig {
	var vaultConfig VaultConfig
	annotations := obj.GetAnnotations()

	vaultConfig.Addr = annotations["vault.security/vault-addr"]
	vaultConfig.Role = annotations["vault.security/vault-role"]
	vaultConfig.Path = annotations["vault.security/vault-path"]
	vaultConfig.Enabled, _ = strconv.ParseBool(annotations["vault.security/enabled"])
	vaultConfig.TLSSecretName = annotations["vault.security/vault-tls-secret-name"]

	return vaultConfig
}

// VaultSecretsMutator if object is Pod mutate pod specs
// return a stop boolean to stop executing the chain and also an error.
func VaultSecretsMutator(ctx context.Context, obj metav1.Object) (bool, error) {
	var podSpec *corev1.PodSpec
	var namespace string

	switch v := obj.(type) {
	case *corev1.Pod:
		podSpec = &v.Spec
	default:
		return false, nil
	}

	vaultConfig := parseVaultConfig(obj)

	// Get namespace from object, if not found check addmission request namespace
	ns := obj.GetNamespace()
	if len(ns) > 0 {
		namespace = ns
	} else {
		namespace = whcontext.GetAdmissionRequest(ctx).Namespace
	}

	/// Verify all annotations ar set
	if vaultConfig.Enabled {
		if vaultConfig.Addr == "" {
			return true, fmt.Errorf("Error getting vault address - make sure you set the annotation \"vault.security/enabled\" on the Pod")
		}
		if vaultConfig.TLSSecretName == "" {
			return true, fmt.Errorf("Error getting vault TLS secret name - make sure you set the annotation \"vault.security/vault-tls-secret-name\"")
		}
		if vaultConfig.Path == "" {
			return true, fmt.Errorf("Error getting vault path - make sure you set the annotation \"vault.security/vault-path\"")
		}
		if vaultConfig.Role == "" {
			return true, fmt.Errorf("Error getting vault role - make sure you set the annotation \"vault.security/vault-role\"")
		}
		if vaultConfig.Addr == "" {
			return true, fmt.Errorf("Error getting vault address - make sure you set the annotation \"vault.security/vault-addr\"")
		}

		return false, MutatePodSpec(obj, podSpec, vaultConfig, namespace)
	}
	// If there's no annotation of  "vault.security/enabled", continue the mutation chain(if there is one) and don't do nothing.
	return false, nil
}

// InitConfig init flags with viper
func InitConfig() {
	viper.SetDefault("vault_env_image", "innovia/vault-env:1.1.0")
	viper.AutomaticEnv()
}

func handlerFor(config mutating.WebhookConfig, mutator mutating.Mutator, logger log.Logger) http.Handler {
	webhook, err := mutating.NewWebhook(config, mutator, nil, nil, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	handler, err := whhttp.HandlerFor(webhook)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating webhook: %s", err)
		os.Exit(1)
	}

	return handler
}

// Main function run webhook
func Main() {
	InitConfig()

	logger := &log.Std{Debug: viper.GetBool("debug")}

	mutator := mutating.MutatorFunc(VaultSecretsMutator)

	podHandler := handlerFor(
		mutating.WebhookConfig{Name: "vault-secrets-webhook-pods", Obj: &corev1.Pod{}},
		mutator,
		logger,
	)

	mux := http.NewServeMux()
	mux.Handle("/pods", podHandler)

	logger.Infof("Listening with TLS on :8443")
	err := http.ListenAndServeTLS(
		":8443",
		viper.GetString("tls_cert_file"),
		viper.GetString("tls_private_key_file"),
		mux,
	)
	if err != nil {

		fmt.Fprintf(os.Stderr, "error serving webhook: %s", err)
		os.Exit(1)
	}
}
