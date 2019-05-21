package tests

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	wh "github.com/innovia/vault-secrets-webhook/webhookmain"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVaultEnvInjectionPodMutate(t *testing.T) {
	testCases := []struct {
		name    string
		pod     *corev1.Pod
		envVars []*corev1.EnvVar
		expPod  *corev1.Pod
		expErr  bool
	}{
		{
			name: "Should not mutate pod when annotation vault.security/enabled does not exist",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-with-no-annotation",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init",
							Image: "some-image",
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "main",
							Image:   "alpine",
							Command: []string{"command"},
							Args:    []string{"with", "extra", "args"},
							Env: []corev1.EnvVar{
								{
									Name:  "SOME_VAR",
									Value: "12345678",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "EmptyDir",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
			expPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-with-no-annotation",
					Namespace: "default",
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:  "init",
							Image: "some-image",
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "main",
							Image:   "alpine",
							Command: []string{"command"},
							Args:    []string{"with", "extra", "args"},
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name:  "SOME_VAR",
									Value: "12345678",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "EmptyDir",
							VolumeSource: corev1.VolumeSource{
								EmptyDir: &corev1.EmptyDirVolumeSource{},
							},
						},
					},
				},
			},
		}, {
			name: "Mutating should happen when annotation vault.security/enabled exists",
			pod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-with-no-annotation",
					Namespace: "default",
					Annotations: map[string]string{
						"vault.security/enabled":               "true",
						"vault.security/vault-addr":            "https://vault.default.svc.cluster.local:8200",
						"vault.security/vault-role":            "some-role",
						"vault.security/vault-path":            "/secret/some/path",
						"vault.security/vault-tls-secret-name": "vault-consul-ca",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine",
							Command: []string{"user-command"},
							Args:    []string{"with", "extra", "args"},
							Env: []corev1.EnvVar{
								corev1.EnvVar{
									Name:  "AWS_SECRET_ACCESS_KEY",
									Value: "vault:AWS_SECRET_ACCESS_KEY",
								},
							},
						},
					},
				},
			},
			expPod: &corev1.Pod{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-pod-with-no-annotation",
					Namespace: "default",
					Annotations: map[string]string{
						"vault.security/enabled":               "true",
						"vault.security/vault-addr":            "https://vault.default.svc.cluster.local:8200",
						"vault.security/vault-role":            "some-role",
						"vault.security/vault-path":            "/secret/some/path",
						"vault.security/vault-tls-secret-name": "vault-consul-ca",
					},
				},
				Spec: corev1.PodSpec{
					InitContainers: []corev1.Container{
						{
							Name:            "init",
							Image:           "innovia/vault-env:1.1.0",
							ImagePullPolicy: corev1.PullIfNotPresent,
							Command:         []string{"sh", "-c", "cp /usr/local/bin/vault-env /vault/"},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "vault-env",
									MountPath: "/vault",
								},
							},
						},
					},
					Containers: []corev1.Container{
						{
							Name:    "alpine",
							Image:   "alpine",
							Command: []string{"/vault/vault-env"},
							Args:    []string{"user-command", "with", "extra", "args"},
							Env: []corev1.EnvVar{
								{
									Name:  "AWS_SECRET_ACCESS_KEY",
									Value: "vault:AWS_SECRET_ACCESS_KEY",
								}, {
									Name:  "VAULT_ADDR",
									Value: "https://vault.default.svc.cluster.local:8200",
								}, {
									Name:  "VAULT_PATH",
									Value: "/secret/some/path",
								}, {
									Name:  "VAULT_ROLE",
									Value: "some-role",
								}, {
									Name:  "VAULT_CAPATH",
									Value: "/etc/tls/ca.pem",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "vault-env",
									MountPath: "/vault",
								}, {
									Name:      "tls",
									MountPath: "/etc/tls",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
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
									SecretName: "vault-consul-ca",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert := assert.New(t)
			actualPod := testCase.pod
			expectedPod := testCase.expPod
			wh.InitConfig()
			_, err := wh.VaultSecretsMutator(context.TODO(), actualPod)
			if testCase.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				t.Log("Checking Env Vars match")
				if diff := deep.Equal(actualPod.Spec.Containers[0].Env, expectedPod.Spec.Containers[0].Env); diff != nil {
					t.Errorf(
						"Env vars mismatch;\n\n expected: %#v\n\n got: %#v\n\nDiff:%#v",
						expectedPod.Spec.Containers[0].Env,
						actualPod.Spec.Containers[0].Env,
						diff,
					)
				}

				t.Log("Checking init container match")
				if diff := deep.Equal(actualPod.Spec.InitContainers, expectedPod.Spec.InitContainers); diff != nil {
					t.Errorf(
						"Init containers mismatch;\n\n expected: %#v\n\n got: %#v\n\nDiff:%#v",
						expectedPod.Spec.InitContainers,
						actualPod.Spec.InitContainers,
						diff,
					)
				}

				t.Log("Checking Container match")
				if diff := deep.Equal(actualPod.Spec.Containers, expectedPod.Spec.Containers); diff != nil {
					t.Errorf(
						"Main containers mismatch;\n\n expected: %#v\n\n got: %#v\n\nDiff:%#v",
						expectedPod.Spec.Containers,
						actualPod.Spec.Containers,
						diff,
					)
				}

				t.Log("Checking Volumes match")
				if diff := deep.Equal(actualPod.Spec.Volumes, expectedPod.Spec.Volumes); diff != nil {
					t.Errorf(
						"Volumes mismatch;\n\n expected: %#v\n\n got: %#v\n\nDiff:%#v",
						expectedPod.Spec.Volumes,
						actualPod.Spec.Volumes,
						diff,
					)
				}

				t.Log("Checking entire Pod match")
				if diff := deep.Equal(actualPod, expectedPod); diff != nil {
					t.Errorf(
						"Expected Pod does not match actual Pod;\n\n expected: %#v\n\n got: %#v\n\nDiff:%#v",
						expectedPod,
						actualPod,
						diff,
					)
				}
			}
		})
	}
}
