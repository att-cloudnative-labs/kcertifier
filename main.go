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

package main

import (
	"flag"
	"os"
	"time"

	"k8s.io/client-go/kubernetes"

	kcertifierv1alpha1 "github.com/att-cloudnative-labs/kcertifier/api/v1alpha1"
	"github.com/att-cloudnative-labs/kcertifier/controllers"
	certificatesv1beta1 "k8s.io/api/certificates/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	_ "k8s.io/client-go/plugin/pkg/client/auth/gcp"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	_ = clientgoscheme.AddToScheme(scheme)

	_ = kcertifierv1alpha1.AddToScheme(scheme)
	_ = corev1.AddToScheme(scheme)
	_ = certificatesv1beta1.AddToScheme(scheme)
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var allowGlobalImports bool
	var allowGlobalPasswordSecret bool
	var allowNamespaceAutoImport bool
	var checkCertificateValidity bool
	var certValidityGracePeriod string
	flag.StringVar(&metricsAddr, "metrics-addr", ":8080", "The address the metric endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", false,
		"Enable leader election for controller manager. Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&allowGlobalImports, "allow-global-imports", false, "Allow the import of secret data from external namespaces. Source secret needs to be annotated to allow import")
	flag.BoolVar(&allowGlobalPasswordSecret, "allow-global-password-secret", false, "Allow keystore passwords to come from external namespaces. Source secret needs to be annotated to allow this")
	flag.BoolVar(&allowNamespaceAutoImport, "allow-namespace-auto-import", false, "Allow annotated namespaces to automatically import kcertifier from another namespace")
	flag.BoolVar(&checkCertificateValidity, "check-cert-validity", false, "Check certificate expiration on package secrets and replace if expiration is within grace period")
	flag.StringVar(&certValidityGracePeriod, "cert-valid-grace", "720h", "Duration before expiration before replacing certificate in package secret (go duration: s,m,h)")
	flag.Parse()

	ctrl.SetLogger(zap.New(func(o *zap.Options) {
		o.Development = true
	}))

	resync := 300 * time.Second
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsAddr,
		LeaderElection:     enableLeaderElection,
		Port:               9443,
		SyncPeriod:         &resync,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	grace, err := time.ParseDuration(certValidityGracePeriod)
	if err != nil {
		setupLog.Error(err, "invalid duration for cert-valid-grace")
		os.Exit(1)
	}
	if err = (&controllers.KcertifierReconciler{
		Client:                    mgr.GetClient(),
		Log:                       ctrl.Log.WithName("controllers").WithName("Kcertifier"),
		Scheme:                    mgr.GetScheme(),
		Recorder:                  mgr.GetEventRecorderFor("Kcertifier"),
		AllowGlobalImports:        allowGlobalImports,
		AllowGlobalPasswordSecret: allowGlobalPasswordSecret,
		CheckCertificateValidity:  checkCertificateValidity,
		CertificateValidityGrace:  grace,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Kcertifier")
		os.Exit(1)
	}
	if err = (&controllers.NamespaceReconciler{
		Client:                   mgr.GetClient(),
		Log:                      ctrl.Log.WithName("controllers").WithName("Namespace"),
		Scheme:                   mgr.GetScheme(),
		Recorder:                 mgr.GetEventRecorderFor("Kcertifier"),
		AllowNamespaceAutoImport: allowNamespaceAutoImport,
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Namespace")
		os.Exit(1)
	}

	stdClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		setupLog.Error(err, "unable to create stdclient for kcertifier controller")
	}
	if err = (&controllers.CertificateSigningRequestReconciler{
		Client:         mgr.GetClient(),
		Log:            ctrl.Log.WithName("controllers").WithName("CertificateSigningRequest"),
		Scheme:         mgr.GetScheme(),
		Recorder:       mgr.GetEventRecorderFor("Kcertifier"),
		ApprovalClient: stdClient.CertificatesV1beta1(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "CertificateSigningRequest")
		os.Exit(1)
	}
	// +kubebuilder:scaffold:builder

	setupLog.Info("starting manager - v2 renew")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
