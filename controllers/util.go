package controllers

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	kcertifierv1alpha1 "github.com/att-cloudnative-labs/kcertifier/api/v1alpha1"
	"github.com/davecgh/go-spew/spew"
	"hash/fnv"
	v1 "k8s.io/api/core/v1"
	k8srand "k8s.io/apimachinery/pkg/util/rand"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	// FriendlyNameHeader keystore attribute for alias/friendlyName
	FriendlyNameHeader = "friendlyName"
)

func getKcertifierSpecHash(kc *kcertifierv1alpha1.Kcertifier) (string, error) {
	hasher := fnv.New32a()
	hasher.Reset()
	printer := spew.ConfigState{
		Indent:         " ",
		SortKeys:       true,
		DisableMethods: true,
		SpewKeys:       true,
	}
	_, err := printer.Fprintf(hasher, "%#v", kc.Spec)
	if err != nil {
		return "", fmt.Errorf("error getting hash of kcertifier spec: %s", err.Error())
	}

	return k8srand.SafeEncodeString(fmt.Sprint(hasher.Sum32())), nil
}

func isImportsPresentInPkg(secret v1.Secret, pkg kcertifierv1alpha1.Package) bool {
	for _, _import := range pkg.Imports {
		if len(_import.TargetKey) == 0 {
			return false
		}
		if secret.Data[_import.TargetKey] == nil {
			return false
		}
	}
	return true
}

func getPemDataKeys(pkg kcertifierv1alpha1.Package) (string, string) {
	cert, found := pkg.Options[CertDataKeyOption]
	if !found {
		cert = DefaultPemCertDataKey
	}
	key, found := pkg.Options[KeyDataKeyOption]
	if !found {
		key = DefaultPemKeyDataKey
	}
	return cert, key
}

func getP12DataKey(pkg kcertifierv1alpha1.Package) string {
	p12, found := pkg.Options[KeystoreDataKeyOption]
	if !found {
		return DefaultPkcs12DataKey
	}
	return p12
}

func getJksDataKey(pkg kcertifierv1alpha1.Package) string {
	jks, found := pkg.Options[KeystoreDataKeyOption]
	if !found {
		return DefaultJksDataKey
	}
	return jks
}

func createPkcs12(certPemBytes []byte, keyPemBytes []byte, password string, alias string) ([]byte, error) {
	certBlock, _ := pem.Decode(certPemBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("error creating keystore. no pem data found")
	}
	if certBlock.Headers == nil {
		certBlock.Headers = make(map[string]string)
	}
	certBlock.Headers[FriendlyNameHeader] = alias
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing x509 certificate: %s", err.Error())
	}
	keyBlock, _ := pem.Decode(keyPemBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("error creating pkcs12. no pem data found")
	}
	if keyBlock.Headers == nil {
		keyBlock.Headers = make(map[string]string)
	}
	keyBlock.Headers[FriendlyNameHeader] = alias
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing private key from pem: %s", err.Error())
	}

	p12bytes, err := pkcs12.Encode(rand.Reader, key, cert, []*x509.Certificate{}, password)
	if err != nil {
		return nil, fmt.Errorf("error encoding pkcs12: %s", err.Error())
	}
	return p12bytes, nil
}
