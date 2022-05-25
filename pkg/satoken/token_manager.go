// Copyright 2022 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

// This file is a modified version of
// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/token/token_manager.go

package satoken

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/go-logr/logr"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
)

const (
	maxTTL    = 1 * time.Hour
	gcPeriod  = time.Minute
	maxJitter = 10 * time.Second
)

// NewManager returns a new token manager.
func NewManager(c clientset.Interface, log logr.Logger) *Manager {
	m := &Manager{
		getToken: func(name, namespace string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
			log.Info("getting token")
			return c.CoreV1().ServiceAccounts(namespace).CreateToken(context.Background(), name, tr, metav1.CreateOptions{})
		},
		reviewToken: func(token string) (*authenticationv1.TokenReview, error) {
			log.Info("reviewing token")
			return c.AuthenticationV1().TokenReviews().Create(context.Background(), &authenticationv1.TokenReview{
				Spec: authenticationv1.TokenReviewSpec{
					Token: token,
				},
			}, metav1.CreateOptions{})
		},
		cache: make(map[string]*authenticationv1.TokenRequest),
		clock: clock.RealClock{},
		log:   log,
	}
	go wait.Forever(m.cleanup, gcPeriod)
	return m
}

// Manager manages service account tokens for pods.
type Manager struct {

	// cacheMutex guards the cache
	cacheMutex sync.RWMutex
	cache      map[string]*authenticationv1.TokenRequest

	// mocked for testing
	getToken    func(name, namespace string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error)
	reviewToken func(token string) (*authenticationv1.TokenReview, error)
	clock       clock.Clock

	log logr.Logger
}

// GetServiceAccountToken gets a service account token from cache or
// from the TokenRequest API. This process is as follows:
// * Check the cache for the current token request.
// * If the token exists and does not require a refresh, return the current token.
// * Attempt to refresh the token.
// * If the token is refreshed successfully, save it in the cache and return the token.
// * If refresh fails and the old token is still valid, log an error and return the old token.
// * If refresh fails and the old token is no longer valid, return an error
func (m *Manager) GetServiceAccountToken(namespace, name string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
	key := keyFunc(name, namespace, tr)

	ctr, ok := m.get(key)

	if ok && !m.requiresRefresh(ctr) {
		return ctr, nil
	}

	tr, err := m.getToken(name, namespace, tr)
	if err != nil {
		switch {
		case !ok:
			return nil, fmt.Errorf("Fetch token: %v", err)
		case m.requiresRefresh(ctr):
			return nil, fmt.Errorf("Token %s expired and refresh failed: %v", key, err)
		default:
			m.log.Error(err, "Update token", "cacheKey", key)
			return ctr, nil
		}
	}

	m.set(key, tr)
	return tr, nil
}

func (m *Manager) cleanup() {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	for k, tr := range m.cache {
		if m.requiresRefresh(tr) {
			delete(m.cache, k)
		}
	}
}

func (m *Manager) get(key string) (*authenticationv1.TokenRequest, bool) {
	m.cacheMutex.RLock()
	defer m.cacheMutex.RUnlock()
	ctr, ok := m.cache[key]
	return ctr, ok
}

func (m *Manager) set(key string, tr *authenticationv1.TokenRequest) {
	m.cacheMutex.Lock()
	defer m.cacheMutex.Unlock()
	m.cache[key] = tr
}

func (m *Manager) requiresRefresh(tr *authenticationv1.TokenRequest) bool {
	review, err := m.reviewToken(tr.Status.Token)
	if err != nil {
		return true
	}

	return !review.Status.Authenticated
}

func keyFunc(name, namespace string, tr *authenticationv1.TokenRequest) string {
	var exp int64
	if tr.Spec.ExpirationSeconds != nil {
		exp = *tr.Spec.ExpirationSeconds
	}

	return fmt.Sprintf("%q/%q/%#v", name, namespace, exp)
}
