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
	kcertifierv1alpha1 "github.com/att-cloudnative-labs/kcertifier/api/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	certsv1beta1 "k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/record"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
)

const (
	KcertifierNotFoundForCSREvent = "KcertifierNotFoundForCSR"
)

// CertificateSigningRequestReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestReconciler struct {
	client.Client
	Log      logr.Logger
	Scheme   *runtime.Scheme
	Recorder record.EventRecorder

	ApprovalClient certsv1beta1.CertificatesV1beta1Interface
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/approval,verbs=create;update
// +kubebuilder:rbac:groups=kcertifier.atteg.com,resources=kcertifiers,verbs=get;list;watch
// +kubebuilder:rbac:groups=kcertifier.atteg.com,resources=kcertifiers/status,verbs=get;update;patch

func (r *CertificateSigningRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var csr certificatesv1beta1.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		// If deletes need to be handled, check for ErrorNotFound here
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	key, ok := csr.Annotations[KcertifierNamespaceNameAnnotation]
	if !ok {
		return ctrl.Result{}, nil
	}
	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error error splitting meta namespace key: %s", err.Error())
	}

	if csr.Status.Conditions == nil ||
		len(csr.Status.Conditions) == 0 ||
		csr.Status.Conditions[0].Type != certificatesv1beta1.CertificateApproved {

		if err := r.approveCsr(ctx, &csr, namespace, name); err != nil {
			return ctrl.Result{}, fmt.Errorf("error approving csr: %s", err.Error())
		}
		return ctrl.Result{}, nil
	}

	if csr.Status.Certificate != nil && len(csr.Status.Certificate) > 0 {
		if err := r.setSignedInKcertifierStatus(ctx, namespace, name); err != nil {
			return ctrl.Result{}, fmt.Errorf("error setting signed status in kcertifier status: %s", err.Error())
		}
	}

	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1beta1.CertificateSigningRequest{}).
		Complete(r)
}

func (r *CertificateSigningRequestReconciler) setSignedInKcertifierStatus(ctx context.Context, namespace, name string) error {
	r.Log.WithValues("kcName", name).Info("setting signed status in kcertifier")
	namespacedName := types.NamespacedName{Namespace: namespace, Name: name}
	var kc kcertifierv1alpha1.Kcertifier
	if err := r.Get(ctx, namespacedName, &kc); err != nil {
		if errors.IsNotFound(err) {
			r.Log.Info("could not set signed status in kcertifier. not found")
			return nil
		}
		return fmt.Errorf("error getting kcertifier: %s", err.Error())
	}
	kcCopy := kc.DeepCopy()
	kcCopy.Status.CsrStatus = "Signed"
	if err := r.Status().Update(ctx, kcCopy); err != nil {
		return fmt.Errorf("error updating status of kcertifier: %s", err.Error())
	}
	return nil
}

func (r *CertificateSigningRequestReconciler) approveCsr(ctx context.Context, csr *certificatesv1beta1.CertificateSigningRequest, namespace, name string) error {
	// first verify that this csr belongs to a kcertifier
	var kc kcertifierv1alpha1.Kcertifier
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: name}, &kc); err != nil {
		if errors.IsNotFound(err) {
			r.Recorder.Event(csr, WarningEventType, KcertifierNotFoundForCSREvent, "the kcertifier indicated in csr annotations was not found. skipping approval")
			return nil
		}
		return fmt.Errorf("error getting kcertifier for csr: %s", err.Error())
	}
	// TODO this is race condition. appears csr can be created and get to this point before kc status is update with csr name
	// perhaps we check this in reconciler requeue a max number of times
	if kc.Status.CsrName != csr.Name {
		r.Recorder.Event(csr, WarningEventType, KcertifierNotFoundForCSREvent, "the kcertifier indicated in this csr's annotations does not have a matching csr name")
		return nil
	}

	r.Log.WithValues("csrName", csr.Name).Info("approving csr")
	csrCopy := csr.DeepCopy()
	approvalCondition := certificatesv1beta1.CertificateSigningRequestCondition{
		Message: "Approved by Kcertifier Controller",
		Reason:  "platform reasons",
		Type:    certificatesv1beta1.CertificateApproved,
	}
	csrCopy.Status.Conditions = []certificatesv1beta1.CertificateSigningRequestCondition{approvalCondition}
	if _, err := r.ApprovalClient.CertificateSigningRequests().UpdateApproval(csrCopy); err != nil {
		return fmt.Errorf("error updating approved status in csr: %s", err.Error())
	}
	return nil
}
