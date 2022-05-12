package generator

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	tokenKey    = "token"
	saTokenType = "kubernetes.io/service-account-token"
)

//TODO think about if this should be a struct of just a func
//TODO add unit tests
type ServiceAccountLoader struct {
	client client.Client // Used to load service accounts their secrets.
}

func NewServiceAccountLoader(client client.Client) *ServiceAccountLoader {
	return &ServiceAccountLoader{client}
}

func (s *ServiceAccountLoader) Client(ctx context.Context, saName, saNamespace string) (client.Client, error) {
	config, err := s.restConfig(ctx, saName, saNamespace)
	if err != nil {
		return nil, err
	}

	return client.New(config, client.Options{})
}

func (s *ServiceAccountLoader) restConfig(ctx context.Context, saName, saNamespace string) (*rest.Config, error) {
	//Get existing config and override - should we do this another way?
	cfg, err := ctrl.GetConfig()
	if err != nil {
		return nil, err
	}

	token, err := s.serviceAccountToken(ctx, saName, saNamespace)
	if err != nil {
		return nil, err
	}

	cfg.BearerTokenFile = "" //Ensure this is not set.
	cfg.BearerToken = string(token)

	return cfg, nil
}

func (s *ServiceAccountLoader) serviceAccountToken(ctx context.Context, name, namespace string) ([]byte, error) {
	sa := corev1.ServiceAccount{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &sa); err != nil {
		return nil, fmt.Errorf("unable to fetch service account %s:%s : %s", namespace, name, err)
	}

	if len(sa.Secrets) == 0 {
		return nil, fmt.Errorf("no secrets found for service account %s", name)
	}

	//TODO what to do if there are mutiple secrets?
	secretName := sa.Secrets[0].Name

	secret := corev1.Secret{}
	if err := s.client.Get(ctx, types.NamespacedName{Namespace: namespace, Name: secretName}, &secret); err != nil {
		return nil, fmt.Errorf("failed to fetch secret %s: %s", secretName, err)
	}

	if secret.Type != saTokenType {
		return nil, fmt.Errorf("secret %s is not of type %s", secretName, saTokenType)
	}
	tokenData, tokenFound := secret.Data[tokenKey]

	if !tokenFound {
		return nil, fmt.Errorf("secret %s does not contain token", secretName)
	}

	return tokenData, nil
}
