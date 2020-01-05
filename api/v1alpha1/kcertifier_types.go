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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// KcertifierSpec defines the desired state of Kcertifier
type KcertifierSpec struct {
	// Important: Run "make" to regenerate code after modifying this file
	// +kubebuilder:validation:Optional
	KeyLength int `json:"keyLength,omitempty"`
	// +kubebuilder:validation:Required
	Subject Subject `json:"subject,omitempty"`
	// +kubebuilder:validation:Optional
	Sans []string `json:"sans,omitempty"`
	// +kubebuilder:validation:Required
	Packages []Package `json:"packages,omitempty"`
}

type Subject struct {
	// +kubebuilder:validation:Required
	CommonName string `json:"commonName,omitempty"`
	// +kubebuilder:validation:Optional
	Country string `json:"country,omitempty"`
	// +kubebuilder:validation:Optional
	StateOrProvince string `json:"stateOrProvince,omitempty"`
	// +kubebuilder:validation:Optional
	Locality string `json:"locality,omitempty"`
	// +kubebuilder:validation:Optional
	Organization string `json:"organization,omitempty"`
	// +kubebuilder:validation:Optional
	OrganizationalUnit string `json:"organizationalUnit,omitempty"`
}

type Package struct {
	// +kubebuilder:validation:Required
	Type string `json:"type,omitempty"`
	// +kubebuilder:validation:Required
	Options map[string]string `json:"options,omitempty"`
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName,omitempty"`
	// +kubebuilder:validation:Optional
	Imports []Import `json:"imports,omitempty"`
	// +kubebuilder:validation:Optional
	Labels map[string]string `json:"labels,omitempty"`
	// +kubebuilder:validation:Optional
	Annotations map[string]string `json:"annotations,omitempty"`
}

type Import struct {
	// +kubebuilder:validation:Optional
	Namespace string `json:"namespace,omitempty"`
	// +kubebuilder:validation:Required
	SecretName string `json:"secretName,omitempty"`
	// +kubebuilder:validation:Optional
	SourceKey string `json:"sourceKey"`
	// +kubebuilder:validation:Required
	TargetKey string `json:"targetKey"`
}

// KcertifierStatus defines the observed state of Kcertifier
type KcertifierStatus struct {
	// Important: Run "make" to regenerate code after modifying this fileKcertifierSpecHash string            `json:"kcertifierSpecHash"`
	KcertifierSpecHash string `json:"kcertifierSpecHash"`
	CurrentPackageHash string `json:"currentPackageHash"`
	KeySecretName      string `json:"keySecretName,omitempty"`
	CsrName            string `json:"csrName,omitempty"`
	CsrStatus          string `json:"csrStatus,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:JSONPath=".spec.subject.commonName",name="Common-Name",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.kcertifierSpecHash",name="Spec-Hash",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.currentPackageHash",name="Pkg-Hash",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.keySecretName",name="KeySecret",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.csrName",name="CSRName",type="string"
// +kubebuilder:printcolumn:JSONPath=".status.csrStatus",name="CSRStatus",type="string"

// Kcertifier is the Schema for the kcertifiers API
type Kcertifier struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   KcertifierSpec   `json:"spec,omitempty"`
	Status KcertifierStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// KcertifierList contains a list of Kcertifier
type KcertifierList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Kcertifier `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Kcertifier{}, &KcertifierList{})
}
