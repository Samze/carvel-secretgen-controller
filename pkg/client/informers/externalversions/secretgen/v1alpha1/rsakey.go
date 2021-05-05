// Code generated by informer-gen. DO NOT EDIT.

package v1alpha1

import (
	time "time"

	secretgenv1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen/v1alpha1"
	versioned "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/client/clientset/versioned"
	internalinterfaces "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/client/informers/externalversions/internalinterfaces"
	v1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/client/listers/secretgen/v1alpha1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	runtime "k8s.io/apimachinery/pkg/runtime"
	watch "k8s.io/apimachinery/pkg/watch"
	cache "k8s.io/client-go/tools/cache"
)

// RSAKeyInformer provides access to a shared informer and lister for
// RSAKeys.
type RSAKeyInformer interface {
	Informer() cache.SharedIndexInformer
	Lister() v1alpha1.RSAKeyLister
}

type rSAKeyInformer struct {
	factory          internalinterfaces.SharedInformerFactory
	tweakListOptions internalinterfaces.TweakListOptionsFunc
	namespace        string
}

// NewRSAKeyInformer constructs a new informer for RSAKey type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewRSAKeyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers) cache.SharedIndexInformer {
	return NewFilteredRSAKeyInformer(client, namespace, resyncPeriod, indexers, nil)
}

// NewFilteredRSAKeyInformer constructs a new informer for RSAKey type.
// Always prefer using an informer factory to get a shared informer instead of getting an independent
// one. This reduces memory footprint and number of connections to the server.
func NewFilteredRSAKeyInformer(client versioned.Interface, namespace string, resyncPeriod time.Duration, indexers cache.Indexers, tweakListOptions internalinterfaces.TweakListOptionsFunc) cache.SharedIndexInformer {
	return cache.NewSharedIndexInformer(
		&cache.ListWatch{
			ListFunc: func(options v1.ListOptions) (runtime.Object, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SecretgenV1alpha1().RSAKeys(namespace).List(options)
			},
			WatchFunc: func(options v1.ListOptions) (watch.Interface, error) {
				if tweakListOptions != nil {
					tweakListOptions(&options)
				}
				return client.SecretgenV1alpha1().RSAKeys(namespace).Watch(options)
			},
		},
		&secretgenv1alpha1.RSAKey{},
		resyncPeriod,
		indexers,
	)
}

func (f *rSAKeyInformer) defaultInformer(client versioned.Interface, resyncPeriod time.Duration) cache.SharedIndexInformer {
	return NewFilteredRSAKeyInformer(client, f.namespace, resyncPeriod, cache.Indexers{cache.NamespaceIndex: cache.MetaNamespaceIndexFunc}, f.tweakListOptions)
}

func (f *rSAKeyInformer) Informer() cache.SharedIndexInformer {
	return f.factory.InformerFor(&secretgenv1alpha1.RSAKey{}, f.defaultInformer)
}

func (f *rSAKeyInformer) Lister() v1alpha1.RSAKeyLister {
	return v1alpha1.NewRSAKeyLister(f.Informer().GetIndexer())
}
