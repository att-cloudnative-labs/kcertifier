/*

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"context"
	"fmt"
	"github.com/att-cloudnative-labs/kcertifier/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"
	"strings"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
)

const (
	// ImportKcertifierNamespaceNameAnnotation annotation indicating which kcertifier to import
	ImportKcertifierNamespaceNameAnnotation = "kcertifier.atteg.com/import-kcertifier"
	// ImportKcertifierOverrideCommonNameAnnotation override common name annotation
	ImportKcertifierOverrideCommonNameAnnotation = "kcertifier.atteg.com/override-common-name"
	// ImportKcertifierOverrideSansAnnotation override sans annotation
	ImportKcertifierOverrideSansAnnotation = "kcertifier.atteg.com/override-sans"

	// ImportKcertifierNotFoundEvent event when indicated kcertifier not found
	ImportKcertifierNotFoundEvent = "ImportKcertifierNotFound"
	// ImportKcertifierNotAnnotated event when indicated kcertifier does not have annotation to allow import
	ImportKcertifierNotAnnotated = "ImportKcertifierNotAnnotated"
)

// NamespaceReconciler reconciles a Namespace object
type NamespaceReconciler struct {
	client.Client
	Log                      logr.Logger
	Scheme                   *runtime.Scheme
	Recorder                 record.EventRecorder
	AllowNamespaceAutoImport bool
}

// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=kcertifier.atteg.com,resources=kcertifiers,verbs=get;list;watch;create;update;patch

// Reconcile control loop reconcile function
func (r *NamespaceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var ns corev1.Namespace
	if err := r.Get(ctx, req.NamespacedName, &ns); err != nil {
		// If deletes need to be handled, check for ErrorNotFound here
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	_, ok := ns.Annotations[ImportKcertifierNamespaceNameAnnotation]
	if !ok {
		return ctrl.Result{}, nil
	}

	if !r.AllowNamespaceAutoImport {
		r.Recorder.Event(&ns, WarningEventType, ImportKcertifierNotAllowedEvent, "namespace has kcertifier import annotation(s) but control not set to allow import")
		return ctrl.Result{}, nil
	}

	importNamespace, importName, err := cache.SplitMetaNamespaceKey(ns.Annotations[ImportKcertifierNamespaceNameAnnotation])
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error getting namespace/name from key: %s", err.Error())
	}

	var kc v1alpha1.Kcertifier
	if err := r.Get(ctx, types.NamespacedName{Namespace: importNamespace, Name: importName}, &kc); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(&ns, WarningEventType, ImportKcertifierNotFoundEvent, "namespace has import kcertifier annotations but the kcertifier was not found")
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, fmt.Errorf("error getting kcertifier: %s", err.Error())
	}

	if val, ok := kc.Annotations[AllowGlobalImportAnnotation]; !ok || val != "true" {
		r.Recorder.Event(&ns, WarningEventType, ImportKcertifierNotAnnotated, "namespace has kcertifier import to kcertifier not annotated to allow import")
		return ctrl.Result{}, nil
	}

	var newKc v1alpha1.Kcertifier
	existing := true
	if err := r.Get(ctx, types.NamespacedName{Namespace: ns.Name, Name: kc.Name}, &newKc); err != nil {
		if errors.IsNotFound(err) {
			existing = false
			newKc = v1alpha1.Kcertifier{
				ObjectMeta: v1.ObjectMeta{
					Namespace:   ns.Name,
					Name:        kc.Name,
					Labels:      kc.Labels,
					Annotations: kc.Annotations,
				},
				Spec: kc.Spec,
			}
		} else {
			return ctrl.Result{}, fmt.Errorf("error getting kcertifier: %s", err.Error())
		}
	} else {
		newKc.ObjectMeta.Labels = kc.Labels
		newKc.ObjectMeta.Annotations = kc.Annotations
		newKc.Spec = kc.Spec
	}

	if val, ok := ns.Annotations[ImportKcertifierOverrideCommonNameAnnotation]; ok {
		newKc.Spec.Subject.CommonName = val
	}
	if val, ok := ns.Annotations[ImportKcertifierOverrideSansAnnotation]; ok {
		newKc.Spec.Sans = strings.Split(val, ",")
	}

	if existing {
		if err := r.Update(ctx, &newKc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error updating kcertifier: %s", err.Error())
		}
	} else {
		if err := r.Create(ctx, &newKc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error creating kcertifier: %s", err.Error())
		}
	}

	return ctrl.Result{}, nil
}

// SetupWithManager - sets up reconciler to be called for this resource
func (r *NamespaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Complete(r)
}
