// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen2/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// SecretTemplateLister helps list SecretTemplates.
// All objects returned here must be treated as read-only.
type SecretTemplateLister interface {
	// List lists all SecretTemplates in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.SecretTemplate, err error)
	// SecretTemplates returns an object that can list and get SecretTemplates.
	SecretTemplates(namespace string) SecretTemplateNamespaceLister
	SecretTemplateListerExpansion
}

// secretTemplateLister implements the SecretTemplateLister interface.
type secretTemplateLister struct {
	indexer cache.Indexer
}

// NewSecretTemplateLister returns a new SecretTemplateLister.
func NewSecretTemplateLister(indexer cache.Indexer) SecretTemplateLister {
	return &secretTemplateLister{indexer: indexer}
}

// List lists all SecretTemplates in the indexer.
func (s *secretTemplateLister) List(selector labels.Selector) (ret []*v1alpha1.SecretTemplate, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.SecretTemplate))
	})
	return ret, err
}

// SecretTemplates returns an object that can list and get SecretTemplates.
func (s *secretTemplateLister) SecretTemplates(namespace string) SecretTemplateNamespaceLister {
	return secretTemplateNamespaceLister{indexer: s.indexer, namespace: namespace}
}

// SecretTemplateNamespaceLister helps list and get SecretTemplates.
// All objects returned here must be treated as read-only.
type SecretTemplateNamespaceLister interface {
	// List lists all SecretTemplates in the indexer for a given namespace.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.SecretTemplate, err error)
	// Get retrieves the SecretTemplate from the indexer for a given namespace and name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.SecretTemplate, error)
	SecretTemplateNamespaceListerExpansion
}

// secretTemplateNamespaceLister implements the SecretTemplateNamespaceLister
// interface.
type secretTemplateNamespaceLister struct {
	indexer   cache.Indexer
	namespace string
}

// List lists all SecretTemplates in the indexer for a given namespace.
func (s secretTemplateNamespaceLister) List(selector labels.Selector) (ret []*v1alpha1.SecretTemplate, err error) {
	err = cache.ListAllByNamespace(s.indexer, s.namespace, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.SecretTemplate))
	})
	return ret, err
}

// Get retrieves the SecretTemplate from the indexer for a given namespace and name.
func (s secretTemplateNamespaceLister) Get(name string) (*v1alpha1.SecretTemplate, error) {
	obj, exists, err := s.indexer.GetByKey(s.namespace + "/" + name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("secrettemplate"), name)
	}
	return obj.(*v1alpha1.SecretTemplate), nil
}
