// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	"time"

	v1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen/v1alpha1"
	scheme "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/client/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	rest "k8s.io/client-go/rest"
)

// SecretExportsGetter has a method to return a SecretExportInterface.
// A group's client should implement this interface.
type SecretExportsGetter interface {
	SecretExports(namespace string) SecretExportInterface
}

// SecretExportInterface has methods to work with SecretExport resources.
type SecretExportInterface interface {
	Create(*v1alpha1.SecretExport) (*v1alpha1.SecretExport, error)
	Update(*v1alpha1.SecretExport) (*v1alpha1.SecretExport, error)
	UpdateStatus(*v1alpha1.SecretExport) (*v1alpha1.SecretExport, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.SecretExport, error)
	List(opts v1.ListOptions) (*v1alpha1.SecretExportList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.SecretExport, err error)
	SecretExportExpansion
}

// secretExports implements SecretExportInterface
type secretExports struct {
	client rest.Interface
	ns     string
}

// newSecretExports returns a SecretExports
func newSecretExports(c *SecretgenV1alpha1Client, namespace string) *secretExports {
	return &secretExports{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the secretExport, and returns the corresponding secretExport object, and an error if there is any.
func (c *secretExports) Get(name string, options v1.GetOptions) (result *v1alpha1.SecretExport, err error) {
	result = &v1alpha1.SecretExport{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretexports").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SecretExports that match those selectors.
func (c *secretExports) List(opts v1.ListOptions) (result *v1alpha1.SecretExportList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.SecretExportList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretexports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested secretExports.
func (c *secretExports) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("secretexports").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a secretExport and creates it.  Returns the server's representation of the secretExport, and an error, if there is any.
func (c *secretExports) Create(secretExport *v1alpha1.SecretExport) (result *v1alpha1.SecretExport, err error) {
	result = &v1alpha1.SecretExport{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("secretexports").
		Body(secretExport).
		Do().
		Into(result)
	return
}

// Update takes the representation of a secretExport and updates it. Returns the server's representation of the secretExport, and an error, if there is any.
func (c *secretExports) Update(secretExport *v1alpha1.SecretExport) (result *v1alpha1.SecretExport, err error) {
	result = &v1alpha1.SecretExport{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretexports").
		Name(secretExport.Name).
		Body(secretExport).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *secretExports) UpdateStatus(secretExport *v1alpha1.SecretExport) (result *v1alpha1.SecretExport, err error) {
	result = &v1alpha1.SecretExport{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretexports").
		Name(secretExport.Name).
		SubResource("status").
		Body(secretExport).
		Do().
		Into(result)
	return
}

// Delete takes name of the secretExport and deletes it. Returns an error if one occurs.
func (c *secretExports) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretexports").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *secretExports) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretexports").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched secretExport.
func (c *secretExports) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.SecretExport, err error) {
	result = &v1alpha1.SecretExport{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("secretexports").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
