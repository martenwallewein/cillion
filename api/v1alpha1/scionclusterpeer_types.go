package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ScionClusterPeerSpec defines the desired state of ScionClusterPeer
type ScionClusterPeerSpec struct {
	// RemoteAS is the SCION ISD-AS of the remote cluster (e.g., "64-ffaa:0:1102")
	RemoteAS string `json:"remoteAS"`

	// PodCIDR is the IP subnet assigned to the remote cluster's pods
	PodCIDR string `json:"podCIDR"`
}

// ScionClusterPeerStatus defines the observed state of ScionClusterPeer
type ScionClusterPeerStatus struct {
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// ScionClusterPeer is the Schema for the scionclusterpeers API
type ScionClusterPeer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitzero"`

	Spec   ScionClusterPeerSpec   `json:"spec"`
	Status ScionClusterPeerStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// ScionClusterPeerList contains a list of ScionClusterPeer
type ScionClusterPeerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []ScionClusterPeer `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ScionClusterPeer{}, &ScionClusterPeerList{})
}
