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
	kcertifierv1alpha1 "github.com/att-cloudnative-labs/kcertifier/api/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/cache"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/pavel-v-chernykh/keystore-go"
	"k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/record"
	"software.sslmate.com/src/go-pkcs12"
	"strings"
)

const (
	// AllowGlobalImportAnnotation allow import from other namespaces annotation
	AllowGlobalImportAnnotation = "kcertifier.atteg.com/allow-global-import"
	// GlobalPasswordSecretAnnotation secret containing keystore password annotation
	GlobalPasswordSecretAnnotation = "kcertifier.atteg.com/global-password-secret"
	// KcertifierSpecHashAnnotation kcertifier spec hash value annotation
	KcertifierSpecHashAnnotation = "kcertifier.atteg.com/kcertifier-spec-hash"
	// KcertifierNamespaceNameAnnotation kcertifier namespace/name annotation
	KcertifierNamespaceNameAnnotation = "kcertifier.atteg.com/kcertifier-namespace-name"

	// DefaultKeyLength default key length
	DefaultKeyLength = 2048
	// DefaultPemKeyDataKey default pem data key
	DefaultPemKeyDataKey = "key.pem"
	// DefaultPemCertDataKey default pem cert key
	DefaultPemCertDataKey = "cert.pem"
	// DefaultPkcs12DataKey default pkcs12 data key
	DefaultPkcs12DataKey = "keystore.p12"
	// DefaultJksDataKey default jks data key
	DefaultJksDataKey = "keystore.jks"
	// DefaultKeystoreAlias default keystore alias
	DefaultKeystoreAlias = "1"

	// PrivateKeyPemType type header for private key pem block
	PrivateKeyPemType = "PRIVATE KEY"
	// CertificateRequestPemType type header for csr
	CertificateRequestPemType = "CERTIFICATE REQUEST"

	// NormalEventType normal event
	NormalEventType = "Normal"
	// WarningEventType warning event
	WarningEventType = "Warning"
	// BuildingPackageEvent building package event
	BuildingPackageEvent = "BuildingPackage"
	// CreatingCSREvent creating csr event
	CreatingCSREvent = "CreatingCSR"
	// AnnotatingCSREvent annotating csr event
	AnnotatingCSREvent = "AnnotatingCSR"
	// CreatingKeySecretEvent creating key secret event
	CreatingKeySecretEvent = "CreatingKeySecret"
	// DeletingKeySecretEvent deleting key secret event
	DeletingKeySecretEvent = "DeletingKeySecret"
	// DeletingCsrEvent deleting csr event
	DeletingCsrEvent = "DeletingCSR"
	// InvalidKcertifierEvent invalid kcertifier event
	InvalidKcertifierEvent = "InvalidKcertifier"
	// InvalidImportSecretEvent invalid import secret event
	InvalidImportSecretEvent = "InvalidImportSecret"
	// InvalidPasswordSecretEvent invalid password secret event
	InvalidPasswordSecretEvent = "InvalidPasswordSecret"
	// ImportKcertifierNotAllowedEvent import kcertifier not allowed event
	ImportKcertifierNotAllowedEvent = "ImportKcertifierNotAllowed"

	// KeySecretGenerateName key secret generate name
	KeySecretGenerateName = "kcertifier-key-"
	// KeySecretKey key secret data key
	KeySecretKey = "key"
	// CsrGenerateName csr generate name
	CsrGenerateName = "kcertifier-csr-"

	// CertDataKeyOption cert data key option
	CertDataKeyOption = "certDataKey"
	// KeyDataKeyOption key data key option
	KeyDataKeyOption = "keyDataKey"
	// KeystoreDataKeyOption keystore data key option
	KeystoreDataKeyOption = "keystoreDataKey"
	// KeystoreAliasOption keystore alias option
	KeystoreAliasOption = "alias"
	// PasswordSecretNamespaceNameOption password secret namespace name option
	PasswordSecretNamespaceNameOption = "passwordSecretNamespaceName"
	// PasswordSecretKeyOption password secret key option
	PasswordSecretKeyOption = "passwordSecretKey"
)

// KcertifierReconciler reconciles a Kcertifier object
type KcertifierReconciler struct {
	client.Client
	Log                       logr.Logger
	Recorder                  record.EventRecorder
	Scheme                    *runtime.Scheme
	AllowGlobalImports        bool
	AllowGlobalPasswordSecret bool
}

// +kubebuilder:rbac:groups=kcertifier.atteg.com,resources=kcertifiers,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=kcertifier.atteg.com,resources=kcertifiers/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certificates,resources=certificatesigningrequests,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=certificates,resources=certificatesigningrequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=core,resources=events,verbs=create;update;patch

// Reconcile control loop reconcile function
func (r *KcertifierReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()

	var kc kcertifierv1alpha1.Kcertifier
	if err := r.Get(ctx, req.NamespacedName, &kc); err != nil {
		// If deletes need to be handled, check for ErrorNotFound here
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// update hash of kcertifier spec
	hash, err := getKcertifierSpecHash(&kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error getting kcertifier spec hash: %s", err.Error())
	}
	kc.Status.KcertifierSpecHash = hash

	// this is a validation. this should eventually be moved to a validating admission controller
	if kc.Spec.Packages == nil || len(kc.Spec.Packages) == 0 {
		r.Recorder.Event(&kc, WarningEventType, InvalidKcertifierEvent, "kcertifier has no packages")
		return ctrl.Result{}, nil
	}

	// check state: packagesComplete
	ok, err := r.packagesComplete(ctx, &kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error checking the statuses of packages: %s", err.Error())
	}
	if ok {
		// Already desired state, nothing to do
		return ctrl.Result{}, nil
	}

	// check state: componentsPresent
	ok, err = r.componentsPresent(ctx, &kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error checking if components present: %s", err.Error())
	}
	if ok {
		if err := r.buildPackages(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error building packages: %s", err.Error())
		}
		if err := r.Status().Update(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error updating kcertifier status: %s", err.Error())
		}
		return ctrl.Result{}, nil
	}

	// check state: csrExistsAnnotatedNotSigned
	ok, err = r.csrExistsAnnotatedNotSigned(ctx, &kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error checking if csr exists, not signed: %s", err.Error())
	}
	if ok {
		// wait state, noop
		return ctrl.Result{}, nil
	}

	// check state: csrExistsNotAnnotated
	// the reason createCsr doesn't annotate the csr upon creation is a race condition would occur
	// where the csr controller would check the kcertifier's status for it's csr name before this
	// controller updates the kcertifier's status with the name. The separate annotateCsr step causes
	// the csr to be reconciled again after being certain the status has the csr name
	ok, err = r.csrExistsNotAnnotated(ctx, &kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error checking if csr exists, not annotated: %s", err.Error())
	}
	if ok {
		if err := r.annotateCsr(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error annotating csr: %s", err.Error())
		}
		if err := r.Status().Update(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error updating kcertifier status: %s", err.Error())
		}
		return ctrl.Result{}, nil
	}

	// check state: keySecretExists
	ok, err = r.keySecretExists(ctx, &kc)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("error checking for key secret: %s", err.Error())
	}
	if ok {
		if err := r.createCsr(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error creating csr: %s", err.Error())
		}
		if err := r.Status().Update(ctx, &kc); err != nil {
			return ctrl.Result{}, fmt.Errorf("error updating kcertifier status: %s", err.Error())
		}
		return ctrl.Result{}, nil
	}

	// initial: create key secret
	if err := r.createKeySecret(ctx, &kc); err != nil {
		return ctrl.Result{}, fmt.Errorf("error creating key secret: %s", err.Error())
	}
	if err := r.Status().Update(ctx, &kc); err != nil {
		return ctrl.Result{}, fmt.Errorf("error updating kcertifier status: %s", err.Error())
	}
	return ctrl.Result{}, nil
}

// SetupWithManager - sets up reconciler to be called for this resource
func (r *KcertifierReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&kcertifierv1alpha1.Kcertifier{}).
		Complete(r)
}

func (r *KcertifierReconciler) packagesComplete(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) (bool, error) {
	// Check that for each package, the secret exists, has the up-to-date hash, has the desired keys, and has all imports
	for _, pkg := range kc.Spec.Packages {
		// check secret exist
		var secret v1.Secret
		err := r.getPackageSecret(ctx, pkg, kc, &secret)
		if err != nil && errors.IsNotFound(err) {
			return false, nil
		} else if err != nil {
			return false, fmt.Errorf("error getting package secret: %s", err.Error())
		}
		// Check package keys present
		if !isCertAndKeyPresentInPkg(secret, pkg, kc.Status.KcertifierSpecHash) {
			return false, nil
		}
		// Check imports present
		if !isImportsPresentInPkg(secret, pkg) {
			return false, nil
		}
	}
	return true, nil
}

// Certificate can either be already in package (even if csr doesn't exists) or inside existing, approved csr
// This allows a state where a package only needs imports added in addition to obvious state of approved csr
func (r *KcertifierReconciler) componentsPresent(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) (bool, error) {
	for _, pkg := range kc.Spec.Packages {
		var secret v1.Secret
		if err := r.getPackageSecret(ctx, pkg, kc, &secret); err != nil {
			if !errors.IsNotFound(err) {
				return false, fmt.Errorf("error getting package secret: %s", err.Error())
			}
		} else {
			if isCertAndKeyPresentInPkg(secret, pkg, kc.Status.KcertifierSpecHash) {
				continue
			}
		}

		if len(kc.Status.CsrName) == 0 {
			return false, nil
		}

		var csr v1beta1.CertificateSigningRequest
		err := r.getKcertifierCsr(ctx, kc, &csr)
		if err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error getting csr: %s", err.Error())
		}
		foundHash, ok := csr.Annotations[KcertifierSpecHashAnnotation]
		if !ok || foundHash != kc.Status.KcertifierSpecHash {
			return false, nil
		}
		if csr.Status.Certificate == nil || len(csr.Status.Certificate) == 0 {
			return false, nil
		}

		var keySecret v1.Secret
		if err := r.getKeySecret(ctx, kc, &keySecret); err != nil {
			if errors.IsNotFound(err) {
				return false, nil
			}
			return false, fmt.Errorf("error getting key secret: %s", err.Error())
		}
		foundHash, ok = keySecret.Annotations[KcertifierSpecHashAnnotation]
		if !ok || foundHash != kc.Status.KcertifierSpecHash {
			return false, nil
		}
		if _, ok := keySecret.Data[KeySecretKey]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (r *KcertifierReconciler) keySecretExists(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) (bool, error) {
	if len(kc.Status.KeySecretName) == 0 {
		return false, nil
	}
	namespaceName := types.NamespacedName{Namespace: kc.Namespace, Name: kc.Status.KeySecretName}
	var secret v1.Secret
	if err := r.Get(ctx, namespaceName, &secret); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	return secret.Data[KeySecretKey] != nil, nil
}

func (r *KcertifierReconciler) createKeySecret(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	r.Recorder.Event(kc, NormalEventType, CreatingKeySecretEvent, CreatingKeySecretEvent)
	random := rand.Reader
	keyLength := DefaultKeyLength
	if kc.Spec.KeyLength > 0 {
		keyLength = kc.Spec.KeyLength
	}
	key, err := rsa.GenerateKey(random, keyLength)
	if err != nil {
		return fmt.Errorf("error generating rsa key: %s", err.Error())
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("error marshalling private key: %s", err.Error())
	}

	keyPemBlock := pem.Block{
		Type:  PrivateKeyPemType,
		Bytes: keyBytes,
	}
	keyPemBytesBuffer := bytes.Buffer{}
	if err := pem.Encode(&keyPemBytesBuffer, &keyPemBlock); err != nil {
		return fmt.Errorf("error pem encoding private key: %s", err.Error())
	}

	secret := v1.Secret{
		ObjectMeta: v12.ObjectMeta{
			Namespace:    kc.Namespace,
			GenerateName: KeySecretGenerateName,
			Annotations: map[string]string{
				KcertifierSpecHashAnnotation: kc.Status.KcertifierSpecHash,
			},
		},
		Data: map[string][]byte{
			KeySecretKey: keyPemBytesBuffer.Bytes(),
		},
	}
	if err := r.Create(ctx, &secret); err != nil {
		return fmt.Errorf("error creating secret: %s", err.Error())
	}

	// set key secret name in status
	kc.Status.KeySecretName = secret.Name
	return nil
}

func (r *KcertifierReconciler) buildPackages(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	for _, pkg := range kc.Spec.Packages {
		existingSecret := true
		var secret v1.Secret
		err := r.getPackageSecret(ctx, pkg, kc, &secret)
		if client.IgnoreNotFound(err) != nil {
			return fmt.Errorf("error getting existing package secret, %s: %s", pkg.SecretName, err.Error())
		}
		if err != nil && errors.IsNotFound(err) {
			existingSecret = false
			secret = v1.Secret{
				ObjectMeta: v12.ObjectMeta{
					Namespace:   kc.Namespace,
					Name:        pkg.SecretName,
					Labels:      pkg.Labels,
					Annotations: pkg.Annotations,
				},
			}
		}
		secretCopy := secret.DeepCopy()
		if secretCopy.Data == nil {
			secretCopy.Data = map[string][]byte{}
		}
		if secretCopy.Data == nil {
			secretCopy.Data = map[string][]byte{}
		}
		switch strings.ToLower(pkg.Type) {
		case "pem":
			if err := r.buildPemPackage(ctx, pkg, kc, secretCopy); err != nil {
				return fmt.Errorf("error building pem package: %s", err.Error())
			}
		case "pkcs12":
			if err := r.buildPkcs12Package(ctx, pkg, kc, secretCopy); err != nil {
				return fmt.Errorf("error building pkcs12 package: %s", err.Error())
			}
		case "jks":
			if err := r.buildJksPackage(ctx, pkg, kc, secretCopy); err != nil {
				return fmt.Errorf("error building jks package: %s", err.Error())
			}
		default:
			return fmt.Errorf("invalid package type, %s", pkg.Type)
		}
		// add imports
		if err := r.addImportsToPackage(ctx, pkg, kc, secretCopy); err != nil {
			return fmt.Errorf("error adding imports to package: %s", err.Error())
		}
		// update kcertifier spec hash
		if secretCopy.Annotations == nil {
			secretCopy.Annotations = make(map[string]string)
		}
		secretCopy.Annotations[KcertifierSpecHashAnnotation] = kc.Status.KcertifierSpecHash
		// create/update package
		if existingSecret {
			if err := r.Update(ctx, secretCopy); err != nil {
				return fmt.Errorf("error updating package secret: %s", err.Error())
			}
		} else if err := r.Create(ctx, secretCopy); err != nil {
			return fmt.Errorf("error creating package secret: %s", err.Error())
		}
	}
	if err := r.deleteKcertifierKeySecretIfExists(ctx, kc); err != nil {
		return fmt.Errorf("error deleting key secret: %s", err)
	}
	if err := r.deleteKcertifierCsrIfExists(ctx, kc); err != nil {
		return fmt.Errorf("error deleting csr: %s", err.Error())
	}
	kc.Status.CurrentPackageHash = kc.Status.KcertifierSpecHash
	kc.Status.KeySecretName = ""
	kc.Status.CsrName = ""
	kc.Status.CsrStatus = ""
	return nil
}

func (r *KcertifierReconciler) buildPemPackage(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier, secret *v1.Secret) error {
	r.Recorder.Event(kc, NormalEventType, BuildingPackageEvent, BuildingPackageEvent)
	certDataKey, keyDataKey := getPemDataKeys(pkg)
	// This implies that if the package already has any non-null value for the keys, it must already be up-to-date
	// Eventually this should check against some sort of hash/version of kcertifier spec and possibly the CA version/hash
	if !isCertAndKeyPresentInPkg(*secret, pkg, kc.Status.KcertifierSpecHash) {
		certBytes, err := r.retrieveCertFromCsr(ctx, kc)
		if err != nil {
			return fmt.Errorf("error retrieving cert from csr: %s", err.Error())
		}
		keyBytes, err := r.getKeyFromKeySecret(ctx, kc)
		if err != nil {
			return fmt.Errorf("error retrieving key from key secret: %s", err.Error())
		}
		secret.Data[certDataKey] = certBytes
		secret.Data[keyDataKey] = keyBytes
	}
	return nil
}

func (r *KcertifierReconciler) buildPkcs12Package(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier, secret *v1.Secret) error {
	r.Recorder.Event(kc, NormalEventType, BuildingPackageEvent, BuildingPackageEvent)
	pkcs12DataKey := getP12DataKey(pkg)
	// This implies that if the package already has any non-null value for the keys, it must already be up-to-date
	// Eventually this should check against some sort of hash/version of kcertifier spec and possibly the CA version/hash
	if !isCertAndKeyPresentInPkg(*secret, pkg, kc.Status.KcertifierSpecHash) {
		certBytes, err := r.retrieveCertFromCsr(ctx, kc)
		if err != nil {
			return err
		}
		keyBytes, err := r.getKeyFromKeySecret(ctx, kc)
		if err != nil {
			return fmt.Errorf("error getting key from key secret: %s", err.Error())
		}
		password, err := r.getKeystorePassword(ctx, pkg, kc)
		if err != nil {
			return fmt.Errorf("error getting keystore password: %s", err.Error())
		}
		alias, ok := pkg.Options[KeystoreAliasOption]
		if !ok {
			alias = DefaultKeystoreAlias
		}
		pkcs12Bytes, err := createPkcs12(certBytes, keyBytes, password, alias)
		if err != nil {
			return fmt.Errorf("error creating pkcs12 for kcertifier, %s: %s", kc.Name, err.Error())
		}
		secret.Data[pkcs12DataKey] = pkcs12Bytes
	}
	return nil
}

func (r *KcertifierReconciler) buildJksPackage(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier, secret *v1.Secret) error {
	r.Recorder.Event(kc, NormalEventType, BuildingPackageEvent, BuildingPackageEvent)
	jksDataKey := getJksDataKey(pkg)
	if !isCertAndKeyPresentInPkg(*secret, pkg, kc.Status.KcertifierSpecHash) {
		certBytes, err := r.retrieveCertFromCsr(ctx, kc)
		if err != nil {
			return fmt.Errorf("error retrieving cert from csr: %s", err.Error())
		}
		certBlock, _ := pem.Decode(certBytes)
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing certificate from pem block: %s", err.Error())
		}
		keyBytes, err := r.getKeyFromKeySecret(ctx, kc)
		if err != nil {
			return err
		}
		keyBlock, _ := pem.Decode(keyBytes)
		alias, ok := pkg.Options[KeystoreAliasOption]
		if !ok {
			alias = DefaultKeystoreAlias
		}

		ks := map[string]interface{}{
			alias: &keystore.PrivateKeyEntry{
				PrivKey: keyBlock.Bytes,
				CertChain: []keystore.Certificate{
					{
						Type:    "X509",
						Content: cert.Raw,
					},
				},
			},
		}
		passwordBytes, err := r.getKeystorePassword(ctx, pkg, kc)
		if err != nil {
			return fmt.Errorf("error getting keystore password: %s", err.Error())
		}
		ksBytes := bytes.Buffer{}
		if err := keystore.Encode(&ksBytes, ks, []byte(passwordBytes)); err != nil {
			return fmt.Errorf("error building java keystore: %s", err.Error())
		}
		secret.Data[jksDataKey] = ksBytes.Bytes()
	}
	return nil
}

func (r *KcertifierReconciler) addImportsToPackage(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier, secret *v1.Secret) error {
	for _, _import := range pkg.Imports {
		if !r.AllowGlobalImports && (len(_import.Namespace) > 0 && _import.Namespace != kc.Namespace) {
			r.Recorder.Event(kc, WarningEventType, ImportKcertifierNotAllowedEvent, "the namespace indicated in the import is external when allow-global-imports is not set on controller")
			continue
		}
		var namespace string
		if len(_import.Namespace) > 0 {
			namespace = _import.Namespace
		} else {
			namespace = secret.Namespace
		}
		var importSecret v1.Secret
		namespacedName := types.NamespacedName{Namespace: namespace, Name: _import.SecretName}
		if err := r.Get(ctx, namespacedName, &importSecret); err != nil {
			if errors.IsNotFound(err) {
				r.Recorder.Event(kc, WarningEventType, InvalidImportSecretEvent, "import for kcertifier package does not exist")
				// we will just skip import and continue
				continue
			} else {
				return fmt.Errorf("error getting import secret: %s", err.Error())
			}
		}
		if importSecret.Namespace != kc.Namespace {
			annotationVal, ok := importSecret.Annotations[AllowGlobalImportAnnotation]
			if !ok || strings.ToLower(annotationVal) != "true" {
				r.Recorder.Event(kc, WarningEventType, InvalidImportSecretEvent, "desired import in external namespace does not have the global import annotation")
				return fmt.Errorf("indicated import secret is in external namespace and does not have global import annotation")
			}
		}
		if importSecret.Data[_import.SourceKey] == nil {
			r.Recorder.Event(kc, WarningEventType, InvalidImportSecretEvent, "import secret does not have the indicated source key")
			continue
		}
		secret.Data[_import.TargetKey] = importSecret.Data[_import.SourceKey]
	}
	return nil
}

func (r *KcertifierReconciler) createCsr(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	r.Recorder.Event(kc, NormalEventType, CreatingCSREvent, CreatingCSREvent)
	keyBytes, err := r.getKeyFromKeySecret(ctx, kc)
	if err != nil {
		return fmt.Errorf("error getting key from key secret: %s", err.Error())
	}

	keyPemBlock, _ := pem.Decode(keyBytes)
	key, err := x509.ParsePKCS8PrivateKey(keyPemBlock.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing private key: %s", err.Error())
	}

	subject := kc.Spec.Subject
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         subject.CommonName,
			Country:            []string{subject.Country},
			Province:           []string{subject.StateOrProvince},
			Locality:           []string{subject.Locality},
			Organization:       []string{subject.Organization},
			OrganizationalUnit: []string{subject.OrganizationalUnit},
		},
		DNSNames: kc.Spec.Sans,
	}

	random := rand.Reader
	csrBytes, err := x509.CreateCertificateRequest(random, &template, key)
	if err != nil {
		return fmt.Errorf("error generating x509 csr: %s", err.Error())
	}

	pemBlock := pem.Block{
		Type:  CertificateRequestPemType,
		Bytes: csrBytes,
	}
	pemBytes := bytes.Buffer{}
	if err := pem.Encode(&pemBytes, &pemBlock); err != nil {
		return fmt.Errorf("error encoding csr to pem: %s", err.Error())
	}

	csr := v1beta1.CertificateSigningRequest{
		ObjectMeta: v12.ObjectMeta{
			GenerateName: CsrGenerateName,
			Annotations: map[string]string{
				KcertifierSpecHashAnnotation: kc.Status.KcertifierSpecHash,
			},
		},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request: pemBytes.Bytes(),
		},
	}

	if err := r.Create(ctx, &csr); err != nil {
		return fmt.Errorf("error creating csr: %s", err.Error())
	}

	kc.Status.CsrName = csr.Name
	kc.Status.CsrStatus = "created"
	return nil
}

func (r *KcertifierReconciler) annotateCsr(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	r.Recorder.Event(kc, NormalEventType, AnnotatingCSREvent, "Annotating CSR")
	var csr v1beta1.CertificateSigningRequest
	if err := r.getKcertifierCsr(ctx, kc, &csr); err != nil {
		return fmt.Errorf("error getting csr: %s", err.Error())
	}

	key, err := cache.MetaNamespaceKeyFunc(kc)
	if err != nil {
		return fmt.Errorf("error extracting namespace name key from kcertifier: %s", err.Error())
	}
	csrCopy := csr.DeepCopy()
	csrCopy.Annotations[KcertifierNamespaceNameAnnotation] = key
	if err := r.Update(ctx, csrCopy); err != nil {
		return fmt.Errorf("error updating csr: %s", err.Error())
	}
	kc.Status.CsrStatus = "annotated"
	return nil
}

func (r *KcertifierReconciler) getKeyFromKeySecret(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) ([]byte, error) {
	var secret v1.Secret
	if err := r.getKeySecret(ctx, kc, &secret); err != nil {
		return nil, fmt.Errorf("error getting key secret: %s", err.Error())
	}
	if secret.Data[KeySecretKey] == nil {
		return nil, fmt.Errorf("key secret does not contain key data")
	}
	return secret.Data[KeySecretKey], nil
}

func (r *KcertifierReconciler) deleteKcertifierKeySecretIfExists(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	if len(kc.Status.KeySecretName) == 0 {
		return nil
	}
	var keySecret v1.Secret
	if err := r.getKeySecret(ctx, kc, &keySecret); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("error getting key secret: %s", err.Error())
	}
	kc.Status.KeySecretName = ""
	r.Recorder.Event(kc, NormalEventType, DeletingKeySecretEvent, DeletingKeySecretEvent)
	return r.Delete(ctx, &keySecret)
}

func (r *KcertifierReconciler) deleteKcertifierCsrIfExists(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) error {
	if len(kc.Status.CsrName) == 0 {
		return nil
	}
	var csr v1beta1.CertificateSigningRequest
	if err := r.getKcertifierCsr(ctx, kc, &csr); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("error getting csr: %s", err.Error())
	}
	kc.Status.CsrName = ""
	r.Recorder.Event(kc, NormalEventType, DeletingCsrEvent, fmt.Sprintf("deleting csr, %s, for kcertifier, %s", csr.Name, kc.Name))
	return r.Delete(ctx, &csr)
}

func (r *KcertifierReconciler) csrExistsAnnotatedNotSigned(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) (bool, error) {
	if len(kc.Status.CsrName) == 0 {
		return false, nil
	}

	var csr v1beta1.CertificateSigningRequest
	if err := r.getKcertifierCsr(ctx, kc, &csr); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("error getting csr: %s", err.Error())
	}
	hash, ok := csr.Annotations[KcertifierSpecHashAnnotation]
	if !ok || hash != kc.Status.KcertifierSpecHash {
		return false, nil
	}
	_, ok = csr.Annotations[KcertifierNamespaceNameAnnotation]
	if !ok {
		return false, nil
	}
	return csr.Status.Certificate == nil || len(csr.Status.Certificate) == 0, nil
}

func (r *KcertifierReconciler) csrExistsNotAnnotated(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) (bool, error) {
	if len(kc.Status.CsrName) == 0 {
		return false, nil
	}

	var csr v1beta1.CertificateSigningRequest
	if err := r.getKcertifierCsr(ctx, kc, &csr); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("error getting csr: %s", err.Error())
	}
	hash, ok := csr.Annotations[KcertifierSpecHashAnnotation]
	if !ok || hash != kc.Status.KcertifierSpecHash {
		return false, nil
	}
	_, ok = csr.Annotations[KcertifierNamespaceNameAnnotation]
	return !ok, nil
}

func (r *KcertifierReconciler) retrieveCertFromCsr(ctx context.Context, kc *kcertifierv1alpha1.Kcertifier) ([]byte, error) {
	var csr v1beta1.CertificateSigningRequest
	if err := r.getKcertifierCsr(ctx, kc, &csr); err != nil {
		return nil, fmt.Errorf("error getting csr: %s", err.Error())
	}
	return csr.Status.Certificate, nil
}

func (r *KcertifierReconciler) getKeystorePassword(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier) (string, error) {
	_, ok := pkg.Options[PasswordSecretNamespaceNameOption]
	if ok {

		var passwordSecret v1.Secret
		if err := r.getPasswordSecret(ctx, pkg, kc, &passwordSecret); err != nil {
			r.Recorder.Event(kc, WarningEventType, InvalidPasswordSecretEvent, fmt.Sprintf("fallback to default keystore password. attempt to retrieve indicated password secret returned error: %s", err.Error()))
			return pkcs12.DefaultPassword, nil
		}

		if passwordSecret.Namespace != kc.Namespace {
			if val, ok := passwordSecret.Annotations[GlobalPasswordSecretAnnotation]; !ok || val != "true" {
				r.Recorder.Event(kc, WarningEventType, InvalidPasswordSecretEvent, "fallback to default keystore password. password secret is in external namespaces and is not annotated to allow global password import")
				return pkcs12.DefaultPassword, nil
			}
		}

		var key string
		if key, ok = pkg.Options[PasswordSecretKeyOption]; !ok {
			if len(passwordSecret.Data) != 1 {
				r.Recorder.Event(kc, WarningEventType, InvalidPasswordSecretEvent, "fallback to default keystore password. password secret key not indicated and password secret does not have exactly one data entry")
				return pkcs12.DefaultPassword, nil
			}

		}
		password, ok := passwordSecret.Data[key]
		if !ok {
			r.Recorder.Event(kc, WarningEventType, InvalidPasswordSecretEvent, "fallback to default keystore password. indicated password secret key does not exist")
			return pkcs12.DefaultPassword, nil
		}
		return string(password), nil
	}
	return pkcs12.DefaultPassword, nil
}

func (r *KcertifierReconciler) getPackageSecret(ctx context.Context, p kcertifierv1alpha1.Package, k *kcertifierv1alpha1.Kcertifier, s *v1.Secret) error {
	namespacedName := types.NamespacedName{
		Namespace: k.Namespace,
		Name:      p.SecretName,
	}
	return r.Get(ctx, namespacedName, s)
}

func (r *KcertifierReconciler) getKcertifierCsr(ctx context.Context, k *kcertifierv1alpha1.Kcertifier, csr *v1beta1.CertificateSigningRequest) error {
	if len(k.Status.CsrName) == 0 {
		return fmt.Errorf("expected csrName to be in status of kcertifier, %s", k.Name)
	}
	namespacedName := types.NamespacedName{
		Name: k.Status.CsrName,
	}
	return r.Get(ctx, namespacedName, csr)
}

func (r *KcertifierReconciler) getKeySecret(ctx context.Context, k *kcertifierv1alpha1.Kcertifier, s *v1.Secret) error {
	if len(k.Status.KeySecretName) == 0 {
		return fmt.Errorf("expected kcertifier to have keySecretName in status while attempting to retrieve key")
	}
	namespacedName := types.NamespacedName{
		Namespace: k.Namespace,
		Name:      k.Status.KeySecretName,
	}
	return r.Get(ctx, namespacedName, s)
}

func (r *KcertifierReconciler) getPasswordSecret(ctx context.Context, pkg kcertifierv1alpha1.Package, kc *kcertifierv1alpha1.Kcertifier, s *v1.Secret) error {
	key, ok := pkg.Options[PasswordSecretNamespaceNameOption]
	if !ok {
		return fmt.Errorf("error getting password secret key option, not found in pkg")
	}

	namespace, name, err := cache.SplitMetaNamespaceKey(key)
	if err != nil {
		return fmt.Errorf("error getting kcertifier namespace and name from annotation value")
	}

	if len(namespace) == 0 {
		namespace = kc.Namespace
	}

	if !r.AllowGlobalPasswordSecret && namespace != kc.Namespace {
		r.Recorder.Event(kc, WarningEventType, InvalidPasswordSecretEvent, "indicated password secret in external namespace when allow-global-password-secret is not set on controller")
		return fmt.Errorf("indicated password secret in external namespace when allow-global-password-secret is not set on controller")
	}

	namespacedName := types.NamespacedName{
		Namespace: namespace,
		Name:      name,
	}
	//TODO VALIDATE GlobalPasswordSecretAnnotation
	return r.Get(ctx, namespacedName, s)
}
