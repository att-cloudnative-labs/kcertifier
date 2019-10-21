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
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"software.sslmate.com/src/go-pkcs12"
	"strings"

	"github.com/go-logr/logr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
)

// SecretReconciler reconciles a Secret object
type SecretReconciler struct {
	client.Client
	Log logr.Logger
}

type SecretState struct {
	OutputsUpdated bool
}

type OutputOption struct {
	Type string
	Source string
	Key string
}

func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		Complete(r)
}

// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=core,resources=secrets/status,verbs=get;update;patch

func (r *SecretReconciler) Reconcile(req ctrl.Request) (ctrl.Result, error) {
	ctx := context.Background()
	_ = r.Log.WithValues("secret", req.NamespacedName)


	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if secret.Annotations[CertificateSecretAnnotation] != "true" {
		return ctrl.Result{}, nil
	}

	state := SecretState{}
	if err := r.getSecretState(ctx, secret, &state); err != nil {
		r.Log.Error(err, "error getting secret state")
	}

	if !state.OutputsUpdated {
		return ctrl.Result{}, r.updateOutputs(ctx, secret)
	}

	return ctrl.Result{}, nil
}


func (r *SecretReconciler) getSecretState(ctx context.Context, secret corev1.Secret, state *SecretState) error {
	outputs, err := getOutputList(secret)
	if err != nil {
		return err
	}
	for _, output := range outputs {
		var outputSecret corev1.Secret
		namespacedName := types.NamespacedName{Namespace:secret.Namespace, Name: output.Name}
		if err := r.Get(ctx, namespacedName, &outputSecret); err != nil {
			if errors.IsNotFound(err){
				// return (output state still false if any not found
				return nil
			}
			return err
		}
		if len(outputSecret.Data[output.Key]) == 0 {
			// key not present; not updated
			return nil
		}
	}
	state.OutputsUpdated = true
	return nil
}

func (r *SecretReconciler) updateOutputs(ctx context.Context, secret corev1.Secret) error {
	outputList, err := getOutputList(secret)
	if err != nil {
		return err
	}

	for _, outputFormat := range outputList {
		switch strings.ToLower(outputFormat.Type) {
		case strings.ToLower("pkcs12"):
			if err := r.updateP12Output(ctx, outputFormat, secret); err != nil {
				return err
			}
		case strings.ToLower("crt"):
			if err := r.updatePemOutput(ctx, outputFormat, secret, CertKeySecretCertDataKey); err != nil {
				return err
			}
		case strings.ToLower("key"):
			if err := r.updatePemOutput(ctx, outputFormat, secret, CertKeySecretKeyDataKey); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported output type: %s", outputFormat.Type)
		}
	}

	return nil
}

func (r *SecretReconciler) updateCrtOutput(ctx context.Context, outputFormat OutputFormat, certSecret corev1.Secret) error {
	namespacedName := types.NamespacedName{Namespace: certSecret.Namespace, Name: outputFormat.Name}
	var outputSecret corev1.Secret
	err := r.Get(ctx, namespacedName, & outputSecret)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		outputSecret = corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Namespace: namespacedName.Namespace,
				Name: namespacedName.Name,
			},
			Data: map[string][]byte{
				outputFormat.Key: certSecret.Data[CertKeySecretCertDataKey],
			},
		}

		if len(outputFormat.Opts) > 0 {
			if err := r.applyOptions(ctx, &outputSecret, outputFormat.Opts); err != nil {
				return err
			}
		}
	} else {
		outputSecret.Data[outputFormat.Key] = certSecret.Data[CertKeySecretCertDataKey]
		if err := r.Update(ctx, &outputSecret); err != nil {
			return err
		}
	}
	return nil
}

func (r *SecretReconciler) updatePemOutput(ctx context.Context, outputFormat OutputFormat, certSecret corev1.Secret, dataKey string) error {
	namespacedName := types.NamespacedName{Namespace: certSecret.Namespace, Name: outputFormat.Name}
	var outputSecret corev1.Secret
	err := r.Get(ctx, namespacedName, & outputSecret)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		outputSecret = corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Namespace: namespacedName.Namespace,
				Name: namespacedName.Name,
			},
			Data: map[string][]byte{
				outputFormat.Key: certSecret.Data[dataKey],
			},
		}

		if len(outputFormat.Opts) > 0 {
			if err := r.applyOptions(ctx, &outputSecret, outputFormat.Opts); err != nil {
				return err
			}
		}
		if err := r.Create(ctx, &outputSecret); err != nil {
			return err
		}
	} else {
		outputSecret.Data[outputFormat.Key] = certSecret.Data[dataKey]
		if err := r.Update(ctx, &outputSecret); err != nil {
			return err
		}
	}
	return nil
}

func (r *SecretReconciler) updateP12Output(ctx context.Context, outputFormat OutputFormat, certSecret corev1.Secret) error {
	keystore, err := getPKCS12(certSecret.Data[CertKeySecretCertDataKey], certSecret.Data[CertKeySecretKeyDataKey], "changit")
	if err != nil {
		r.Log.Error(err, "error retrieving keystore from certificate/key")
		return err
	}

	keystoreData := []byte(keystore)

	keystoreNamespaceName := types.NamespacedName{Namespace: certSecret.Namespace, Name: outputFormat.Name}
	var keystoreSecret corev1.Secret
	err = r.Get(ctx, keystoreNamespaceName, &keystoreSecret)
	if err != nil && !errors.IsNotFound(err) {
		return err
	}
	if errors.IsNotFound(err) {
		keystoreSecret = corev1.Secret{
			ObjectMeta: v1.ObjectMeta{
				Namespace: keystoreNamespaceName.Namespace,
				Name:      keystoreNamespaceName.Name,
			},
			Data: map[string][]byte{
				outputFormat.Key: keystoreData,
			},
		}

		if len(outputFormat.Opts) > 0 {
			if err := r.applyOptions(ctx, &keystoreSecret, outputFormat.Opts); err != nil {
				return err
			}
		}
		if err := r.Create(ctx, &keystoreSecret); err != nil {
			return err
		}
	} else {
		keystoreSecret.Data[outputFormat.Key] = keystoreData
		if err := r.Update(ctx, &keystoreSecret); err != nil {
			return err
		}
	}
	return nil
}

func (r *SecretReconciler) applyOptions(ctx context.Context, secret *corev1.Secret, opt string) error {
	optionParams := strings.Split(opt, OutputsOptionsSeparator)
	if len(optionParams) != 3 {
		return fmt.Errorf("invalid format for output option: %s. format is type:source:key", opt)
	}
	option := OutputOption{
		Type: optionParams[0],
		Source: optionParams[1],
		Key: optionParams[2],
	}

	switch strings.ToLower(option.Type) {
	case strings.ToLower("copykey"):
		if err := r.applyCopyKeyOption(ctx, secret, option); err != nil {
			return err
		}
	default:
		return fmt.Errorf("invalid output option type: %s", option.Type)
	}
	return nil
}

func (r *SecretReconciler) applyCopyKeyOption(ctx context.Context, secret *corev1.Secret, option OutputOption) error {
	sourceNamespaceNameKey := strings.Split(option.Source, OutputOptionSourceSeparator)
	if len(sourceNamespaceNameKey) != 3 {
		return fmt.Errorf("invalid source for copykey: %s. format is namespace/name/key", option.Source)
	}
	var sourceSecret corev1.Secret
	if err := r.Get(ctx, types.NamespacedName{Namespace: sourceNamespaceNameKey[0], Name: sourceNamespaceNameKey[1]}, &sourceSecret); err != nil {
		return err
	}
	// TODO validate source before applying
	secret.Data[option.Key] = sourceSecret.Data[sourceNamespaceNameKey[2]]
	return nil
}

func getPKCS12(certPemBytes []byte, keyPemBytes []byte, password string) ([]byte, error) {
	certBlock, _ := pem.Decode(certPemBytes)
	if certBlock == nil {
		return nil, fmt.Errorf("error creating keystore. no pem data found")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error creating keystore, couldn't parse cert from pem: %s", err.Error())
	}

	keyBlock, _ := pem.Decode(keyPemBytes)
	if keyBlock == nil {
		return nil, fmt.Errorf("error creating keystore. no pem data found")
	}

	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error creating keystore, couldn't parse key from pem: %s", err.Error())
	}

	return pkcs12.Encode(rand.Reader, key, cert, []*x509.Certificate{}, password)
}

func getOutputList(secret corev1.Secret) ([]OutputFormat, error) {
	outputs := secret.Annotations[OutputsAnnotation]
	if len(outputs) == 0 {
		return []OutputFormat{}, nil
	}
	outputsStringArray := strings.Split(outputs, OutputsSeparator)
	outputFormats := make([]OutputFormat,0)
	for _, outputString := range outputsStringArray {
		params := strings.Split(outputString, OutputsParamsSeparator)
		if len(params) != 3 && len(params) != 4 {
			return []OutputFormat{}, fmt.Errorf("error parsing outputs annotation. invalid number of params in %s", params)
		}
		newOutputFormat := OutputFormat{Name: params[0], Type: params[1], Key: params[2]}
		if len(params) == 4 {
			newOutputFormat.Opts = params[3]
		}
		outputFormats = append(outputFormats, newOutputFormat)

	}
	return outputFormats, nil
}