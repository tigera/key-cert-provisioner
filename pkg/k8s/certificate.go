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
	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/tigera/key-cert-provisioner/pkg/cfg"
	"github.com/tigera/key-cert-provisioner/pkg/tls"

	"k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// WatchCSR Watches the CSR resource for updates and writes results to the certificate location (which should be mounted as an emptyDir)
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
		if chcsr.Name == cfg.CSRName && chcsr.Status.Conditions != nil && len(chcsr.Status.Certificate) > 0 {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				if c.Type == v1beta1.CertificateApproved && (c.Status == v1.ConditionTrue || c.Status == "") { //status unset should be treated as true for backwards compatibility.
					approved = true
					break
				}
				if c.Type == v1beta1.CertificateDenied && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR was denied for this pod. CSR name: %s", cfg.CSRName)
				}
				if c.Type == v1beta1.CertificateFailed && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR failed for this pod. CSR name: %s", cfg.CSRName)
				}
			}
			if approved {
				log.Infof("the CSR has been signed and approved, writing to certificate location: %v", cfg.EmptyDirLocation)

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
				return nil
			}
		}
	}
	return nil
}

// SubmitCSR Submits a CSR in order to obtain a signed certificate for this pod.
func SubmitCSR(ctx context.Context, config *cfg.Config, restClient *RestClient, x509CSR *tls.X509CSR) error {
	cli := restClient.Clientset.CertificatesV1beta1().CertificateSigningRequests()
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: config.CSRName,
			Labels: map[string]string{
				"k8s-app": config.Label,
			}},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:    x509CSR.CSR,
			SignerName: &config.Signer,
			Usages:     []v1beta1.KeyUsage{v1beta1.UsageServerAuth, v1beta1.UsageDigitalSignature, v1beta1.UsageKeyAgreement},
		},
	}

	created, err := cli.Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		if errors.IsAlreadyExists(err) {
			// If this is the case, it means this pod crashed previously. We need to delete the CSR and re-submit a new CSR,
			// otherwise we end up with a private key that does not match the issued cert.
			if err = cli.Delete(ctx, config.CSRName, metav1.DeleteOptions{}); err != nil {
				return err
			}
			if created, err = cli.Create(ctx, csr, metav1.CreateOptions{}); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("crashed while trying to create Kubernetes certificate signing request: %w", err)
		}
	}

	log.Infof("created CSR: %v", created)
	return nil
}
