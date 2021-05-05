// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// SecretExportLister helps list SecretExports.
type SecretExportLister interface {
	// List lists all SecretExports in the indexer.
	List(selector labels.Selector) (ret []*v1alpha1.SecretExport, err error)
	// SecretExports returns an object that can list and get SecretExports.
	SecretExports(namespace string) SecretExportNamespaceLister
	SecretExportListerExpansion
}

// secretExportLister implements the SecretExportLister interface.
type secretExportLister struct {
	indexer cache.Indexer
}

// NewSecretExportLister returns a new SecretExportLister.
func NewSecretExportLister(indexer cache.Indexer) SecretExportLister {
	return &secretExportLister{indexer: indexer}
}

// List lists all SecretExports in the indexer.
func (s *secretExportLister) List(selector labels.Selector) (ret []*v1alpha1.SecretExport, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.SecretExport))
	})
	return ret, err
}

// SecretExports returns an object that can list and get SecretExports.
func (s *secretExportLister) SecretExports(namespace string) SecretExportNamespaceLister {
	return secretExportNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// SecretExportNamespaceLister helps list and get SecretExports.
type SecretExportNamespaceLister interface {
	// List lists all SecretExports in the indexer for a given namespace.
	List(selector labels.Selector) (ret []*v1alpha1.SecretExport, err error)
	// Get retrieves the SecretExport from the indexer for a given namespace and name.
	Get(name string) (*v1alpha1.SecretExport, error)
	SecretExportNamespaceListerExpansion
}

// secretExportNamespaceLister implements the SecretExportNamespaceLister
// interface.
type secretExportNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all SecretExports in the indexer for a given namespace.
func (s secretExportNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.SecretExport, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.SecretExport))
	})
	return ret, err
}

// Get retrieves the SecretExport from the indexer for a given namespace and name.
func (s secretExportNamespaceLister) Get(name string) (*v1alpha1.SecretExport, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("secretexport"), name)
	}
	return obj.(*v1alpha1.SecretExport), nil
}
