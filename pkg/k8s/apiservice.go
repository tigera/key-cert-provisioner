// Copyright (c) 2021 Tigera, Inc. All rights reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

const (
	// Constants for creating the tigera-apiserver
	apiServerNamespace = "tigera-system"
	apiServiceName     = "tigera-api"
	calicoAPIGroup     = "projectcalico.org"
	aapiVersionGroup   = "v3.projectcalico.org"
)

// RegisterApiServer creates a registration for this pod to run as an aggregated apiserver.
func RegisterAPIService(ctx context.Context, restClient *RestClient, caBundle []byte) error {
	apiService := &apiregistrationv1beta1.APIService{
		TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: aapiVersionGroup,
		},
		Spec: apiregistrationv1beta1.APIServiceSpec{
			Group:                calicoAPIGroup,
			VersionPriority:      200,
			GroupPriorityMinimum: 1500,
			Service: &apiregistrationv1beta1.ServiceReference{
				Name:      apiServiceName,
				Namespace: apiServerNamespace,
			},
			Version:  "v3",
			CABundle: caBundle,
		},
	}

	existing, err := restClient.APIRegistrationClient.APIServices().Get(ctx, aapiVersionGroup, metav1.GetOptions{})
	if err == nil {
		// It exists already, so we must update it.
		existing.Spec = apiService.Spec
		_, err = restClient.APIRegistrationClient.APIServices().Update(ctx, existing, metav1.UpdateOptions{})
	} else if errors.IsNotFound(err) {
		// Create the apiservice
		_, err = restClient.APIRegistrationClient.APIServices().Create(ctx, apiService, metav1.CreateOptions{})
	}

	if err != nil {
		return fmt.Errorf("error during api service registration for: %w", err)
	}
	return nil
}
