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

// PasswordsGetter has a method to return a PasswordInterface.
// A group's client should implement this interface.
type PasswordsGetter interface {
	Passwords(namespace string) PasswordInterface
}

// PasswordInterface has methods to work with Password resources.
type PasswordInterface interface {
	Create(*v1alpha1.Password) (*v1alpha1.Password, error)
	Update(*v1alpha1.Password) (*v1alpha1.Password, error)
	UpdateStatus(*v1alpha1.Password) (*v1alpha1.Password, error)
	Delete(name string, options *v1.DeleteOptions) error
	DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error
	Get(name string, options v1.GetOptions) (*v1alpha1.Password, error)
	List(opts v1.ListOptions) (*v1alpha1.PasswordList, error)
	Watch(opts v1.ListOptions) (watch.Interface, error)
	Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Password, err error)
	PasswordExpansion
}

// passwords implements PasswordInterface
type passwords struct {
	client rest.Interface
	ns     string
}

// newPasswords returns a Passwords
func newPasswords(c *SecretgenV1alpha1Client, namespace string) *passwords {
	return &passwords{
		client: c.RESTClient(),
		ns:     namespace,
	}
}

// Get takes name of the password, and returns the corresponding password object, and an error if there is any.
func (c *passwords) Get(name string, options v1.GetOptions) (result *v1alpha1.Password, err error) {
	result = &v1alpha1.Password{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("passwords").
		Name(name).
		VersionedParams(&options, scheme.ParameterCodec).
		Do().
		Into(result)
	return
}

// List takes label and field selectors, and returns the list of Passwords that match those selectors.
func (c *passwords) List(opts v1.ListOptions) (result *v1alpha1.PasswordList, err error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	result = &v1alpha1.PasswordList{}
	err = c.client.Get().
		Namespace(c.ns).
		Resource("passwords").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Do().
		Into(result)
	return
}

// Watch returns a watch.Interface that watches the requested passwords.
func (c *passwords) Watch(opts v1.ListOptions) (watch.Interface, error) {
	var timeout time.Duration
	if opts.TimeoutSeconds != nil {
		timeout = time.Duration(*opts.TimeoutSeconds) * time.Second
	}
	opts.Watch = true
	return c.client.Get().
		Namespace(c.ns).
		Resource("passwords").
		VersionedParams(&opts, scheme.ParameterCodec).
		Timeout(timeout).
		Watch()
}

// Create takes the representation of a password and creates it.  Returns the server's representation of the password, and an error, if there is any.
func (c *passwords) Create(password *v1alpha1.Password) (result *v1alpha1.Password, err error) {
	result = &v1alpha1.Password{}
	err = c.client.Post().
		Namespace(c.ns).
		Resource("passwords").
		Body(password).
		Do().
		Into(result)
	return
}

// Update takes the representation of a password and updates it. Returns the server's representation of the password, and an error, if there is any.
func (c *passwords) Update(password *v1alpha1.Password) (result *v1alpha1.Password, err error) {
	result = &v1alpha1.Password{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("passwords").
		Name(password.Name).
		Body(password).
		Do().
		Into(result)
	return
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().

func (c *passwords) UpdateStatus(password *v1alpha1.Password) (result *v1alpha1.Password, err error) {
	result = &v1alpha1.Password{}
	err = c.client.Put().
		Namespace(c.ns).
		Resource("passwords").
		Name(password.Name).
		SubResource("status").
		Body(password).
		Do().
		Into(result)
	return
}

// Delete takes name of the password and deletes it. Returns an error if one occurs.
func (c *passwords) Delete(name string, options *v1.DeleteOptions) error {
	return c.client.Delete().
		Namespace(c.ns).
		Resource("passwords").
		Name(name).
		Body(options).
		Do().
		Error()
}

// DeleteCollection deletes a collection of objects.
func (c *passwords) DeleteCollection(options *v1.DeleteOptions, listOptions v1.ListOptions) error {
	var timeout time.Duration
	if listOptions.TimeoutSeconds != nil {
		timeout = time.Duration(*listOptions.TimeoutSeconds) * time.Second
	}
	return c.client.Delete().
		Namespace(c.ns).
		Resource("passwords").
		VersionedParams(&listOptions, scheme.ParameterCodec).
		Timeout(timeout).
		Body(options).
		Do().
		Error()
}

// Patch applies the patch and returns the patched password.
func (c *passwords) Patch(name string, pt types.PatchType, data []byte, subresources ...string) (result *v1alpha1.Password, err error) {
	result = &v1alpha1.Password{}
	err = c.client.Patch(pt).
		Namespace(c.ns).
		Resource("passwords").
		SubResource(subresources...).
		Name(name).
		Body(data).
		Do().
		Into(result)
	return
}
