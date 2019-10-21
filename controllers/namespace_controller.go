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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"k8s.io/api/certificates/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
)

const (
	AutoCertAnnotation        = "kcertifier.atteg.com/enabled"
	OutputsAnnotation = "kcertifier.atteg.com/outputs"
	CSRAnnotation             = "kcertifier.atteg.com/namespace"
	CertificateSecretAnnotation = "kcertifier.atteg.com/certificate"
	CAVersionAnnotation = "kcertifier.atteg.com/ca-version"
	SANsAnnotation = "kcertifier.atteg.com/sans"
	OutputsSeparator = ","
	OutputsParamsSeparator = ";"
	OutputsOptionsSeparator = ":"
	OutputOptionSourceSeparator = "/"
	CertKeySecretName = "kcertifier-cert"
	CertKeySecretCertDataKey  = "cert"
	CertKeySecretKeyDataKey   = "key"
	CsrSuffix                 = "-kcertifier-csr"
	PendingKeyDataKey         = "key-pending"
	KeyLength                 = 2048
	ClusterDomain             = "cluster.local"
	ServiceSubdomain          = "svc"
	PrivateKeyPemType         = "PRIVATE KEY"
	CertificateRequestPemType = "CERTIFICATE REQUEST"
	CloudProviderDomain       = "*.us-west-2.compute.internal"
)

// NamespaceReconciler reconciles a Namespace object
type NamespaceReconciler struct {
	client.Client
	Log logr.Logger
}

type NamespaceState struct {
	HasCert        bool
	HasKey         bool
	HasCSR         bool
	HasApprovedCSR bool
	HasCSRCert     bool
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=namespaces/status,verbs=get;update;patch

func (r *NamespaceReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	log := r.Log.WithValues("namespace", req.NamespacedName)

	var namespace corev1.Namespace
	if err := r.Get(ctx, req.NamespacedName, &namespace); err != nil {
		log.Error(err, "error retrieving namespace")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if namespace.Annotations[AutoCertAnnotation] != "true" {
		return ctrl.Result{}, nil
	}

	state := NamespaceState{}
	if err := r.getNamespaceState(ctx, namespace, &state); err != nil {
		return ctrl.Result{}, err
	}

	if (!state.HasCert || !state.HasKey) && !state.HasCSR {
		return ctrl.Result{}, r.createCSR(ctx, namespace)
	}

	return ctrl.Result{}, nil
}

func getCSRNamespacedName(namespace corev1.Namespace) types.NamespacedName {
	csrName := fmt.Sprintf("%s%s", namespace.Name, CsrSuffix)
	return types.NamespacedName{Namespace: namespace.Name, Name: csrName}
}

func (r *NamespaceReconciler) getNamespaceCSR(ctx context.Context, namespace corev1.Namespace) (v1beta1.CertificateSigningRequest, error) {
	var csr v1beta1.CertificateSigningRequest
	err := r.Get(ctx, getCSRNamespacedName(namespace), &csr)
	return csr, err
}

func (r *NamespaceReconciler) getNamespaceState(ctx context.Context, namespace corev1.Namespace, state *NamespaceState) error {
	if err := r.getStateOfCertKeySecret(ctx, namespace, state); err != nil {
		return err
	}
	if err := r.getStateOfCSR(ctx, namespace, state); err != nil {
		return err
	}
	return nil
}

func (r *NamespaceReconciler) getStateOfCertKeySecret(ctx context.Context, namespace corev1.Namespace, state *NamespaceState) error {
	var certKeySecret corev1.Secret
	err := r.Get(ctx, types.NamespacedName{Namespace: namespace.Name, Name: CertKeySecretName}, &certKeySecret)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		return nil
	}

	if len(certKeySecret.Data[CertKeySecretCertDataKey]) == 0 {
		return nil
	}
	if len(certKeySecret.Data[CertKeySecretKeyDataKey]) == 0 {
		return nil
	}
	if certKeySecret.Annotations[CertificateSecretAnnotation] != "true" {
		return nil
	}
	if certKeySecret.Annotations[OutputsAnnotation] != namespace.Annotations[OutputsAnnotation] {
		return nil
	}
	state.HasCert = true
	return nil
}

func (r *NamespaceReconciler) getStateOfCSR(ctx context.Context, namespace corev1.Namespace, state *NamespaceState) error {
	csr, err := r.getNamespaceCSR(ctx, namespace)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		return nil
	}
	state.HasCSR = true
	if csr.Status.Conditions != nil && csr.Status.Conditions[0].Type == v1beta1.CertificateApproved {
		state.HasApprovedCSR = true
	}
	if len(csr.Status.Certificate) > 0 {
		state.HasCSRCert = true
	}
	return nil
}

func (r *NamespaceReconciler) createCSR(ctx context.Context, namespace corev1.Namespace) error {
	r.Log.V(1).Info("creating csr", "namespace", namespace.Name)

	commonName := fmt.Sprintf("*.%s.%s.%s", namespace.Name, ServiceSubdomain, ClusterDomain)
	san1 := fmt.Sprintf("*.%s", namespace.Name)
	san2 := fmt.Sprintf("*.%s.%s", namespace.Name, ServiceSubdomain)
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         commonName,
			Country:            []string{"US"},
			Province:           []string{"California"},
			Locality:           []string{"El Segundo"},
			Organization:       []string{"AT&T Mobility & Entertainment"},
			OrganizationalUnit: []string{"OV Platform"},
		},
		DNSNames: []string{san1, san2, CloudProviderDomain},
	}

	r.Log.V(1).Info("generating key", "namespace", namespace.Name)
	random := rand.Reader
	key, err := rsa.GenerateKey(random, KeyLength)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		r.Log.Error(err, "error marshalling private key")
		return err
	}

	keyPemBlock := pem.Block{
		Type:  PrivateKeyPemType,
		Bytes: keyBytes,
	}
	keyPemBytes := bytes.Buffer{}
	if err := pem.Encode(&keyPemBytes, &keyPemBlock); err != nil {
		r.Log.Error(err, "error pem encoding private key")
	}
	if err := r.updateSecretWithPendingKey(ctx, namespace.Name, keyPemBytes.Bytes()); err != nil {
		return err
	}

	r.Log.V(1).Info("generatig x509 csr", "namespace", namespace.Name)
	csrBytes, err := x509.CreateCertificateRequest(random, &template, key)
	if err != nil {
		r.Log.Error(err, "error generating csr")
		return err
	}

	pemBlock := pem.Block{
		Type:  CertificateRequestPemType,
		Bytes: csrBytes,
	}
	pemBytes := bytes.Buffer{}
	if err := pem.Encode(&pemBytes, &pemBlock); err != nil {
		r.Log.Error(err, "error encoding csr to pem")
		return err
	}

	csrName := fmt.Sprintf("%s%s", namespace.Name, CsrSuffix)

	//var existingCsr v1beta1.CertificateSigningRequest
	//if err := r.Get(ctx, types.NamespacedName{Name: csrName}, &existingCsr); err != nil && !errors.IsNotFound(err){
	//	return err
	//}
	//if !errors.IsNotFound(err) {
	//	if err := r.Delete(ctx, &existingCsr); err != nil {
	//		return err
	//	}
	//}
	csr := v1beta1.CertificateSigningRequest{
		ObjectMeta: v1.ObjectMeta{
			Name: csrName,
			Annotations: map[string]string{
				CSRAnnotation: namespace.Name,
				OutputsAnnotation: namespace.Annotations[OutputsAnnotation],
			},
		},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request: pemBytes.Bytes(),
		},
	}
	r.Log.V(1).Info("creating kubernetes csr", "namespace", namespace.Name)
	return r.Create(ctx, &csr)
}

func (r *NamespaceReconciler) updateSecretWithPendingKey(ctx context.Context, namespaceName string, pemKey []byte) error {
	newSecret := corev1.Secret{
		ObjectMeta: v1.ObjectMeta{
			Namespace: namespaceName,
			Name:      CertKeySecretName,
		},
		Data: map[string][]byte{PendingKeyDataKey: pemKey}, // TODO should key be const or configurable
	}

	var existingSecret corev1.Secret
	namespacedName := types.NamespacedName{Namespace: namespaceName, Name: CertKeySecretName}
	if err := r.Get(ctx, namespacedName, &existingSecret); err != nil {
		if errors.IsNotFound(err) {
			return r.Create(ctx, &newSecret)
		} else {
			return err
		}
	}

	existingSecret.Data[PendingKeyDataKey] = pemKey
	return r.Update(ctx, &existingSecret)
}

func (r *NamespaceReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Namespace{}).
		Complete(r)
}
