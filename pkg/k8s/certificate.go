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
	"io/ioutil"
	"os"
	"path"

	log "github.com/sirupsen/logrus"

	"github.com/tigera/key-cert-provisioner/pkg/cfg"
	"github.com/tigera/key-cert-provisioner/pkg/tls"

	"k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func WatchCSR(ctx context.Context, restClient *RestClient, cfg *cfg.Config, x509CSR *tls.X509CSR) error {
	watcher, err := restClient.Clientset.CertificatesV1beta1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("unable to watch certificate requests: %w", err)
	}
	log.Infof("watching CSR until it has been signed and approved: %v", cfg.CSRName)
	for event := range watcher.ResultChan() {
		chcsr, ok := event.Object.(*v1beta1.CertificateSigningRequest)
		if !ok {
			return fmt.Errorf("unexpected type in CertificateSigningRequest channel: %w", err)
		}
		if chcsr.Name == cfg.CSRName && chcsr.Status.Conditions != nil && chcsr.Status.Certificate != nil {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				if c.Type == v1beta1.CertificateApproved && c.Status != v1.ConditionFalse {
					approved = true
					break
				}
			}
			if approved {
				log.Infof("the CSR has been signed and approved, writing to secret location: %v", cfg.EmptyDirLocation)

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(cfg.EmptyDirLocation, cfg.CertName), chcsr.Status.Certificate, os.FileMode(0744))
				if err != nil {
					return fmt.Errorf("error while writing to file: %w", err)
				}

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(cfg.EmptyDirLocation, cfg.KeyName), x509CSR.PrivateKeyPEM, os.FileMode(0744))
				if err != nil {
					return fmt.Errorf("error while writing to file: %w", err)
				}

				if cfg.RegisterApiserver {
					return RegisterAPIService(ctx, restClient, chcsr.Status.Certificate)
				}
				break
			}
		}
	}
	return nil
}

func SubmitCSR(ctx context.Context, config *cfg.Config, restClient *RestClient, x509CSR *tls.X509CSR) error {
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta:   metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: config.CSRName},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:    x509CSR.CSR,
			SignerName: &config.Signer,
			Usages:     []v1beta1.KeyUsage{v1beta1.UsageServerAuth, v1beta1.UsageDigitalSignature, v1beta1.UsageKeyAgreement},
		},
	}

	created, err := restClient.Clientset.CertificatesV1beta1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("crashed while trying to create Kubernetes certificate signing request: %w", err)
	}

	log.Infof("created CSR: %v", created)
	return nil
}
