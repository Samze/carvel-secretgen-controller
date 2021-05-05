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

// SecretRequestsGetter has a method to return a SecretRequestInterface.
// A group's client should implement this interface.
type SecretRequestsGetter interface {
	SecretRequests(namespace string) SecretRequestInterface
}

// SecretRequestInterface has methods to work with SecretRequest resources.
type SecretRequestInterface interface {
	Create(*v1alpha1.SecretRequest) (*v1alpha1.SecretRequest, error)
	Update(*v1alpha1.SecretRequest) (*v1alpha1.SecretRequest, error)
	UpdateStatus(*v1alpha1.SecretRequest) (*v1alpha1.SecretRequest, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.SecretRequest, error)
	List(opts v1.ListOptions) (*v1alpha1.SecretRequestList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.SecretRequest, err error)
	SecretRequestExpansion
}

// secretRequests implements SecretRequestInterface
type secretRequests struct {
	client rest.Interface
	ns     string
}

// newSecretRequests returns a SecretRequests
func newSecretRequests(c *SecretgenV1alpha1Client, namespace string) *secretRequests {
	return &secretRequests{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the secretRequest, and returns the corresponding secretRequest object, and an error if there is any.
func (c *secretRequests) Get(name string, options v1.GetOptions) (result *v1alpha1.SecretRequest, err error) {
	result = &v1alpha1.SecretRequest{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretrequests").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of SecretRequests that match those selectors.
func (c *secretRequests) List(opts v1.ListOptions) (result *v1alpha1.SecretRequestList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.SecretRequestList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("secretrequests").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested secretRequests.
func (c *secretRequests) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("secretrequests").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a secretRequest and creates it.  Returns the server's representation of the secretRequest, and an error, if there is any.
func (c *secretRequests) Create(secretRequest *v1alpha1.SecretRequest) (result *v1alpha1.SecretRequest, err error) {
	result = &v1alpha1.SecretRequest{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("secretrequests").
		Body(secretRequest).
		Do().
		Into(result)
	return
}

// Update takes the representation of a secretRequest and updates it. Returns the server's representation of the secretRequest, and an error, if there is any.
func (c *secretRequests) Update(secretRequest *v1alpha1.SecretRequest) (result *v1alpha1.SecretRequest, err error) {
	result = &v1alpha1.SecretRequest{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretrequests").
		Name(secretRequest.Name).
		Body(secretRequest).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *secretRequests) UpdateStatus(secretRequest *v1alpha1.SecretRequest) (result *v1alpha1.SecretRequest, err error) {
	result = &v1alpha1.SecretRequest{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("secretrequests").
		Name(secretRequest.Name).
		SubResource("status").
		Body(secretRequest).
		Do().
		Into(result)
	return
}

// Delete takes name of the secretRequest and deletes it. Returns an error if one occurs.
func (c *secretRequests) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretrequests").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *secretRequests) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("secretrequests").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched secretRequest.
func (c *secretRequests) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.SecretRequest, err error) {
	result = &v1alpha1.SecretRequest{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("secretrequests").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
