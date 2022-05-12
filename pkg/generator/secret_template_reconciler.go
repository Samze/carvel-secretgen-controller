// Copyright 2021 VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package generator

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/go-logr/logr"
	sgv1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen/v1alpha1"
	sg2v1alpha1 "github.com/vmware-tanzu/carvel-secretgen-controller/pkg/apis/secretgen2/v1alpha1"
	"github.com/vmware-tanzu/carvel-secretgen-controller/pkg/client2/clientset/versioned/scheme"
	"github.com/vmware-tanzu/carvel-secretgen-controller/pkg/reconciler"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"k8s.io/client-go/util/jsonpath"
)

type SecretTemplateReconciler struct {
	client   client.Client
	saLoader *ServiceAccountLoader
	log      logr.Logger
}

var _ reconcile.Reconciler = &SecretTemplateReconciler{}

func NewSecretTemplateReconciler(client client.Client, loader *ServiceAccountLoader, log logr.Logger) *SecretTemplateReconciler {
	return &SecretTemplateReconciler{client, loader, log}
}

// AttachWatches adds starts watches this reconciler requires.
func (r *SecretTemplateReconciler) AttachWatches(controller controller.Controller) error {
	//Watch for changes to created Secrets
	if err := controller.Watch(&source.Kind{Type: &corev1.Secret{}}, &handler.EnqueueRequestForOwner{OwnerType: &sg2v1alpha1.SecretTemplate{}}); err != nil {
		return err
	}
	return controller.Watch(&source.Kind{Type: &sg2v1alpha1.SecretTemplate{}}, &handler.EnqueueRequestForObject{})
}

// Reconcile is the entrypoint for incoming requests from k8s
func (r *SecretTemplateReconciler) Reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	log := r.log.WithValues("request", request)

	secretTemplate := sg2v1alpha1.SecretTemplate{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: request.Namespace, Name: request.Name}, &secretTemplate); err != nil {
		if errors.IsNotFound(err) {
			log.Info("Not found")
			return reconcile.Result{}, nil
		}
		return reconcile.Result{}, err
	}

	if secretTemplate.DeletionTimestamp != nil {
		return reconcile.Result{}, nil
	}

	status := &reconciler.Status{
		S:          secretTemplate.Status.GenericStatus,
		UpdateFunc: func(st sgv1alpha1.GenericStatus) { secretTemplate.Status.GenericStatus = st },
	}

	status.SetReconciling(secretTemplate.ObjectMeta)
	defer r.updateStatus(ctx, &secretTemplate)

	return status.WithReconcileCompleted(r.reconcile(ctx, &secretTemplate))
}

func (r *SecretTemplateReconciler) reconcile(ctx context.Context, secretTemplate *sg2v1alpha1.SecretTemplate) (reconcile.Result, error) {

	//Get client to fetch inputResources
	inputResourceclient, err := r.clientForSecretTemplate(secretTemplate)
	if err != nil {
		return reconcile.Result{}, err
	}

	//Resolve input resources
	inputResources, err := resolveInputResources(ctx, secretTemplate, inputResourceclient)
	if err != nil {
		return reconcile.Result{}, err
	}

	//TODO handle existing secret when failing to fetch input resources.
	//When an input resource is deleted or a key is missing we should delete the secret.
	//But should we delete the secret for potentially intermitent errors?

	//Template Secret Data
	secretData := map[string][]byte{}
	for key, expression := range secretTemplate.Spec.JSONPathTemplate.Data {
		valueBuffer, err := jsonPath(expression, inputResources)
		if err != nil {
			//TODO jsonpath error
			//Delete any existing secret?
			return reconcile.Result{}, err
		}

		decoded, err := base64.StdEncoding.DecodeString(valueBuffer.String())
		if err != nil {
			//TODO: this happens when someone is putting a path in .data from a resource value that isn't base64 encoded.
			return reconcile.Result{}, err
		}

		secretData[key] = decoded
	}

	//Template Secret StringData
	secretStringData := map[string]string{}
	for key, expression := range secretTemplate.Spec.JSONPathTemplate.StringData {
		valueBuffer, err := jsonPath(expression, inputResources)
		if err != nil {
			//TODO jsonpath error
			//Delete any existing secret?
			return reconcile.Result{}, err
		}

		secretStringData[key] = valueBuffer.String()
	}

	//Create Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretTemplate.GetName(),
			Namespace: secretTemplate.GetNamespace(),
		},
	}

	controllerutil.SetControllerReference(secretTemplate, secret, scheme.Scheme)

	if _, err := controllerutil.CreateOrUpdate(ctx, r.client, secret, func() error {
		secret.ObjectMeta.Labels = secretTemplate.GetLabels()           //TODO do we want these implicitly?
		secret.ObjectMeta.Annotations = secretTemplate.GetAnnotations() //TODO do we want these implicitly?
		secret.StringData = secretStringData
		secret.Data = secretData
		return nil
	}); err != nil {
		return reconcile.Result{}, err
	}

	//TODO this currently isn't being updated on the resource
	secretTemplate.Status.Secret.Name = secret.Name

	return reconcile.Result{}, nil
}

func (r *SecretTemplateReconciler) updateStatus(ctx context.Context, secretTemplate *sg2v1alpha1.SecretTemplate) error {
	existingSecretTemplate := sg2v1alpha1.SecretTemplate{}
	if err := r.client.Get(ctx, types.NamespacedName{Namespace: secretTemplate.Namespace, Name: secretTemplate.Name}, &existingSecretTemplate); err != nil {
		return fmt.Errorf("fetching secretTemplate: %s", err)
	}

	existingSecretTemplate.Status = secretTemplate.Status

	if err := r.client.Status().Update(ctx, &existingSecretTemplate); err != nil {
		return fmt.Errorf("updating secretTemplate status: %s", err)
	}

	return nil
}

// Returns a client that was created using Service Account specified in the SecretTemplate spec.
// If no service account was specified then it returns the same Client as used by the SecretTemplateReconciler.
func (r *SecretTemplateReconciler) clientForSecretTemplate(secretTemplate *sg2v1alpha1.SecretTemplate) (client.Client, error) {
	c := r.client
	if secretTemplate.Spec.ServiceAccountName != "" {
		saClient, err := r.saLoader.Client(secretTemplate.Spec.ServiceAccountName, secretTemplate.Namespace)
		if err != nil {
			return nil, err
		}
		c = saClient
	}
	return c, nil
}

func resolveInputResources(ctx context.Context, secretTemplate *sg2v1alpha1.SecretTemplate, client client.Client) (map[string]interface{}, error) {
	resolvedInputResources := map[string]interface{}{}

	for _, inputResource := range secretTemplate.Spec.InputResources {
		unstructuredResource, err := resolveInputResource(inputResource.Ref, secretTemplate.Namespace, resolvedInputResources)
		if err != nil {
			return nil, err
		}

		key := types.NamespacedName{Namespace: secretTemplate.Namespace, Name: unstructuredResource.GetName()}

		//TODO: Setup dynamic watch - maybe a first pass periodically re-reconciles (like kapp controller)
		if err := client.Get(ctx, key, &unstructuredResource); err != nil {
			return nil, err
		}

		resolvedInputResources[inputResource.Name] = unstructuredResource.UnstructuredContent()
	}
	return resolvedInputResources, nil
}

func resolveInputResource(ref sg2v1alpha1.InputResourceRef, namespace string, inputResources map[string]interface{}) (unstructured.Unstructured, error) {
	//TODO should we only search for jsonpath expressions in name? Probably.
	resolvedName, err := jsonPath(ref.Name, inputResources)
	if err != nil {
		return unstructured.Unstructured{}, err
	}

	return toUnstructured(ref.APIVersion, ref.Kind, namespace, resolvedName.String())
}

//TODO how does this package from k8s align with our usecases? Do other packages exist?
func jsonPath(expression string, values interface{}) (*bytes.Buffer, error) {
	path := TemplateSyntaxPath(expression)

	//TODO temp for debugging remove (contains sensitive info)
	fmt.Printf("jsonpath before ex: %s, values:%v\n", expression, values)

	//TODO understand if we want allowmissingkeys or not.
	parser := jsonpath.New("").AllowMissingKeys(false)
	err := parser.Parse(path.ToK8sJSONPath())
	if err != nil {
		//todo template error
		return nil, err
	}

	buf := new(bytes.Buffer)
	err = parser.Execute(buf, values)
	if err != nil {
		//todo json path execute error
		return nil, err
	}

	//TODO temp for debugging remove (contains sensitive info)
	fmt.Printf("jsonpath result ex: %s, values:%v res:%s\n", expression, values, buf.String())

	return buf, nil
}

// TODO this is public for unit testing

type stack []string

func (s stack) push(x string) stack {
	return append(s, x)
}

func (s stack) pop() stack {
	return s[:len(s)-1]
}

func (s stack) peek() string {
	if len(s) == 0 {
		return ""
	}

	return s[len(s)-1]
}

type TemplateSyntaxPath string

const (
	leftDelimiter  = "$("
	rightDelimiter = ")"
)

// Count the number of delimiter pairs in the path.
func (p TemplateSyntaxPath) CountDelimiterPairs() int {
	count := 0

	var delimiters stack
	oldPath := string(p)

	for i := range oldPath {
		if i < len(oldPath)-2 && oldPath[i:i+2] == leftDelimiter {
			if delimiters.peek() != leftDelimiter {
				delimiters = delimiters.push(leftDelimiter)
			}
		}
		if string(oldPath[i]) == rightDelimiter {
			if delimiters.peek() == leftDelimiter {
				delimiters = delimiters.pop()
				count += 1
			}
		}
	}

	return count
}

// If the expression contains an opening $( and a closing ), toK8sJSONPath will replace them with a { and a } respectively.
func (p TemplateSyntaxPath) ToK8sJSONPath() string {
	newPath := string(p)
	i := 0
	for pair := 0; pair < p.CountDelimiterPairs(); pair++ {
		for string(newPath[i:i+2]) != leftDelimiter {
			i += 1
		}

		if newPath[i:i+2] == leftDelimiter {
			newPath = replace(newPath, i, leftDelimiter, "{")

			// Skip inner filters and inner $() expressions.
			for string(newPath[i]) != rightDelimiter {
				nextTwo := string(newPath[i : i+2])
				if nextTwo == "?(" || nextTwo == leftDelimiter {
					for string(newPath[i]) != rightDelimiter {
						i += 1
					}
				}

				i += 1
			}

			newPath = replace(newPath, i, rightDelimiter, "}")
		}
	}

	return newPath
}

func replace(s string, i int, old, new string) string {
	if i+len(old) > len(s) {
		return fmt.Sprintf("%s}", s[0:i])
	}
	return strings.Join([]string{s[0:i], s[i+len(old):]}, new)
}

func toUnstructured(apiVersion, kind, namespace, name string) (unstructured.Unstructured, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return unstructured.Unstructured{}, err
	}

	gvk := schema.GroupVersionKind{
		Group:   gv.Group,
		Version: gv.Version,
		Kind:    kind,
	}

	obj := unstructured.Unstructured{}
	obj.SetGroupVersionKind(gvk)
	obj.SetName(name)
	obj.SetNamespace(namespace)

	return obj, nil
}
