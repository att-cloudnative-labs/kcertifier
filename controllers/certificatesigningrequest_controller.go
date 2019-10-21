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
	"github.com/go-logr/logr"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/typed/certificates/v1beta1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CertificateSigningRequestReconciler reconciles a CertificateSigningRequest object
type CertificateSigningRequestReconciler struct {
	client.Client
	Log        logr.Logger
	CertClient v1beta1.CertificatesV1beta1Interface
}

type CSRState struct {
	Approved bool
	CertificateReady bool
	CertificateSecretUpdated bool
	OutputsUpdated bool
}

type OutputFormat struct {
	Name string
	Type string
	Key string
	Opts string
}

func (r *CertificateSigningRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certificatesv1beta1.CertificateSigningRequest{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates.k8s.io,resources=certificatesigningrequests/status,verbs=get;update;patch

func (r *CertificateSigningRequestReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	r.Log.V(1).Info("reconciling csr", "name", req.Name)

	var csr certificatesv1beta1.CertificateSigningRequest
	if err := r.Get(ctx, req.NamespacedName, &csr); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if len(csr.Annotations[CSRAnnotation]) == 0 {
		return ctrl.Result{}, nil
	}

	state := CSRState{}

	// this is effectively a state machine; each state must be distinct and appropriate action will be taken
	if err := r.getCSRState(ctx, csr, &state); err != nil {
		return ctrl.Result{}, err
	}

	if !state.Approved {
		return ctrl.Result{}, r.approveCSR(ctx, csr)
	}

	if !state.CertificateSecretUpdated && state.CertificateReady {
		return ctrl.Result{}, r.retrieveCertificate(ctx, csr)
	}

	return ctrl.Result{}, nil
}

func (r *CertificateSigningRequestReconciler) getCSRState(ctx context.Context, csr certificatesv1beta1.CertificateSigningRequest, state *CSRState) error {
	if csr.Status.Conditions != nil && csr.Status.Conditions[0].Type == "Approved" {
		state.Approved = true
	}
	if csr.Status.Certificate != nil {
		state.CertificateReady = true
	}
	return r.getCertificateSecretState(ctx, csr, state)
}

func (r *CertificateSigningRequestReconciler) getCertificateSecretState(ctx context.Context, csr certificatesv1beta1.CertificateSigningRequest, state *CSRState) error {
	namespace := csr.Annotations[CSRAnnotation]

	var certSecret v1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: CertKeySecretName}, &certSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil
		} else {
			return err
		}
	}
	if len(certSecret.Data[CertKeySecretCertDataKey]) == 0 {
		return nil
	}
	// TODO check that certificate is actually up-to-date
	state.CertificateSecretUpdated = true
	return nil
}

func (r *CertificateSigningRequestReconciler) approveCSR(ctx context.Context, csr certificatesv1beta1.CertificateSigningRequest) error {
	csrCopy := csr.DeepCopy()

	approvalCondition := certificatesv1beta1.CertificateSigningRequestCondition{
		Message: "Approved by KCertifier Controller",
		Reason:  "platform reasons",
		Type:    certificatesv1beta1.CertificateApproved,
	}

	csrCopy.Status.Conditions = []certificatesv1beta1.CertificateSigningRequestCondition{approvalCondition}
	_, err := r.CertClient.CertificateSigningRequests().UpdateApproval(csrCopy)
	return err
}

func (r *CertificateSigningRequestReconciler) retrieveCertificate(ctx context.Context, csr certificatesv1beta1.CertificateSigningRequest) error {
	namespace := csr.Annotations[CSRAnnotation]
	// It is not the job of this reconcile to create the secret, so we can assume the secret is there (and key-pending entry) or its an error
	var existingSecret v1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: namespace, Name: CertKeySecretName}, &existingSecret); err != nil {
		r.Log.Error(err, "error retrieving cert-key secret")
		return err
	}

	if len(existingSecret.Data[PendingKeyDataKey]) == 0 {
		err := fmt.Errorf("missing pending key data in secret")
		r.Log.Error(err, "error setting up certificate secret")
		return err
	}

	secretCopy := existingSecret.DeepCopy()
	if secretCopy.Annotations == nil {
		secretCopy.Annotations = make(map[string]string)
	}
	secretCopy.Annotations[CertificateSecretAnnotation] = "true"
	secretCopy.Annotations[OutputsAnnotation] = csr.Annotations[OutputsAnnotation]
	secretCopy.Data = map[string][]byte{
		CertKeySecretCertDataKey: csr.Status.Certificate,
		CertKeySecretKeyDataKey:  existingSecret.Data[PendingKeyDataKey],
	}
	if err := r.Update(ctx, secretCopy); err != nil {
		r.Log.Error(err, "error updating certificate secret")
	}

	return r.Delete(ctx, &csr)
}



