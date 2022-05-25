// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/vmware-tanzu/carvel-secretgen-controller/pkg/satoken"
	authv1 "k8s.io/api/authentication/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrl "sigs.k8s.io/controller-runtime/pkg/client/config"
)

const (
	tokenKey    = "token"
	caCert      = "ca.crt"
	saTokenType = "kubernetes.io/service-account-token"
)

// ServiceAccountLoader allows the construction of a k8s client from a Service Account
type ServiceAccountLoader struct {
	tokenManager *satoken.Manager
}

// NewServiceAccountLoader creates a new ServiceAccountLoader
func NewServiceAccountLoader(tokenManager *satoken.Manager) *ServiceAccountLoader {
	return &ServiceAccountLoader{
		tokenManager: tokenManager,
	}
}

// Client returns a new k8s client for a Service Account
func (s *ServiceAccountLoader) Client(ctx context.Context, saName, saNamespace string) (client.Client, error) {
	config, err := s.restConfig(ctx, saName, saNamespace)
	if err != nil {
		return nil, err
	}

	return client.New(config, client.Options{})
}

func (s *ServiceAccountLoader) restConfig(ctx context.Context, saName, saNamespace string) (*rest.Config, error) {
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}
	expiration := int64(time.Hour.Seconds())
	tokenRequest, err := s.tokenManager.GetServiceAccountToken(saNamespace, saName, &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			ExpirationSeconds: &expiration,
		},
	})
	if err != nil {
		return nil, err
	}

	var caData []byte
	if len(cfg.CAData) > 0 {
		caData = cfg.CAData
	}
	if cfg.CAFile != "" {
		caData, err = os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
	}

	templatedConfig, err := templateKubeconfig(cfg.Host, tokenRequest.Status.Token, saNamespace, caData)
	if err != nil {
		return nil, err
	}

	return clientcmd.RESTConfigFromKubeConfig([]byte(templatedConfig))
}

func templateKubeconfig(host, token, nsBytes string, caCert []byte) (string, error) {
	const kubeconfigYAMLTpl = `
apiVersion: v1
kind: Config
clusters:
- name: dst-cluster
  cluster:
    certificate-authority-data: "%s"
    server: "%s"
users:
- name: dst-user
  user:
    token: "%s"
contexts:
- name: dst-ctx
  context:
    cluster: dst-cluster
    namespace: "%s"
    user: dst-user
current-context: dst-ctx
`

	caB64Encoded := base64.StdEncoding.EncodeToString(caCert)

	return fmt.Sprintf(kubeconfigYAMLTpl, caB64Encoded, host, []byte(token), []byte(nsBytes)), nil
}
