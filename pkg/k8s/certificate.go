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
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"os"
	"path"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/errors"

	"github.com/tigera/key-cert-provisioner/pkg/cfg"
	"github.com/tigera/key-cert-provisioner/pkg/tls"

	certV1 "k8s.io/api/certificates/v1"
	certV1beta1 "k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type VersionInfo struct {
	Minor int
}

func WatchCSR(ctx context.Context, restClient *RestClient, cfg *cfg.Config, x509CSR *tls.X509CSR) error {
	version, err := getKubernetesVersion(restClient.Clientset)
	if err != nil {
		return err
	}

	watcher, err := createCSRWatcher(ctx, restClient, version, err)
	if err != nil {
		return fmt.Errorf("unable to watch certificate requests: %w", err)
	}
	log.Infof("watching CSR until it has been signed and approved: %v", cfg.CSRName)
	return WatchCSRBasedOnKubernetesVersion(watcher, cfg, x509CSR, version)
}

func createCSRWatcher(ctx context.Context, restClient *RestClient, version *VersionInfo, err error) (*watch.Interface, error) {
	var watcher watch.Interface
	if version != nil && version.Minor > 18 {
		watcher, err = restClient.Clientset.CertificatesV1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	} else {
		watcher, err = restClient.Clientset.CertificatesV1beta1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	}
	return &watcher, err
}

func WatchCSRBasedOnKubernetesVersion(watcher *watch.Interface, cfg *cfg.Config, x509CSR *tls.X509CSR, version *VersionInfo) error {
	if version != nil && version.Minor > 18 {
		return WatchCSRUsingCertV1(watcher, cfg, x509CSR)
	} else {
		return WatchCSRUsingCertV1beta1(watcher, cfg, x509CSR)
	}
}

// WatchCSR Watches the CSR resource for updates and writes results to the certificate location (which should be mounted as an emptyDir)
func WatchCSRUsingCertV1(watcher *watch.Interface, cfg *cfg.Config, x509CSR *tls.X509CSR) error {
	for event := range (*watcher).ResultChan() {
		chcsr, ok := event.Object.(*certV1.CertificateSigningRequest)
		if !ok {
			return fmt.Errorf("unexpected type in CertificateSigningRequest channel: %o", event.Object)
		}
		if chcsr.Name == cfg.CSRName && chcsr.Status.Conditions != nil && len(chcsr.Status.Certificate) > 0 {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				if c.Type == certV1.CertificateApproved && c.Status == v1.ConditionTrue {
					approved = true
					break
				}
				if c.Type == certV1.CertificateDenied && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR was denied for this pod. CSR name: %s", cfg.CSRName)
				}
				if c.Type == certV1.CertificateFailed && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR failed for this pod. CSR name: %s", cfg.CSRName)
				}
			}
			if approved {
				return writeCertificateToFile(cfg, chcsr.Status.Certificate, x509CSR)
			}
		}
	}
	return nil
}

func WatchCSRUsingCertV1beta1(watcher *watch.Interface, cfg *cfg.Config, x509CSR *tls.X509CSR) error {
	for event := range (*watcher).ResultChan() {
		chcsr, ok := event.Object.(*certV1beta1.CertificateSigningRequest)
		if !ok {
			return fmt.Errorf("unexpected type in CertificateSigningRequest channel: %o", event.Object)
		}
		if chcsr.Name == cfg.CSRName && chcsr.Status.Conditions != nil && len(chcsr.Status.Certificate) > 0 {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				//status unset should be treated as true for backwards compatibility.
				if c.Type == certV1beta1.CertificateApproved && (c.Status == v1.ConditionTrue || c.Status == "") {
					approved = true
					break
				}
				if c.Type == certV1beta1.CertificateDenied && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR was denied for this pod. CSR name: %s", cfg.CSRName)
				}
				if c.Type == certV1beta1.CertificateFailed && c.Status == v1.ConditionTrue {
					return fmt.Errorf("CSR failed for this pod. CSR name: %s", cfg.CSRName)
				}
			}
			if approved {
				return writeCertificateToFile(cfg, chcsr.Status.Certificate, x509CSR)
			}
		}
	}
	return nil
}

func writeCertificateToFile(cfg *cfg.Config, cert []byte, x509CSR *tls.X509CSR) error {
	log.Infof("the CSR has been signed and approved, writing to certificate location: %v", cfg.EmptyDirLocation)

	// Give other users read permission to this file.
	err := ioutil.WriteFile(path.Join(cfg.EmptyDirLocation, cfg.CertName), cert, os.FileMode(0744))
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

// SubmitCSR Submits a CSR in order to obtain a signed certificate for this pod.
func SubmitCSR(ctx context.Context, config *cfg.Config, restClient *RestClient, x509CSR *tls.X509CSR) error {
	version, err := getKubernetesVersion(restClient.Clientset)
	if err != nil {
		return err
	}

	if version != nil && version.Minor > 18 {
		return SubmitCSRUsingCertV1(ctx, config, restClient, x509CSR)
	}
	return SubmitCSRUsingCertV1beta1(ctx, config, restClient, x509CSR)
}

func SubmitCSRUsingCertV1(ctx context.Context, config *cfg.Config, restClient *RestClient, x509CSR *tls.X509CSR) error {
	cli := restClient.Clientset.CertificatesV1().CertificateSigningRequests()
	csr := &certV1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: config.CSRName,
			Labels: map[string]string{
				"k8s-app": config.AppName,
			}},
		Spec: certV1.CertificateSigningRequestSpec{
			Request:    x509CSR.CSR,
			SignerName: config.Signer,
			Usages:     []certV1.KeyUsage{certV1.UsageServerAuth, certV1.UsageClientAuth, certV1.UsageDigitalSignature, certV1.UsageKeyAgreement},
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

func SubmitCSRUsingCertV1beta1(ctx context.Context, config *cfg.Config, restClient *RestClient, x509CSR *tls.X509CSR) error {
	cli := restClient.Clientset.CertificatesV1beta1().CertificateSigningRequests()
	csr := &certV1beta1.CertificateSigningRequest{
		TypeMeta: metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{
			Name: config.CSRName,
			Labels: map[string]string{
				"k8s-app": config.AppName,
			}},
		Spec: certV1beta1.CertificateSigningRequestSpec{
			Request:    x509CSR.CSR,
			SignerName: &config.Signer,
			Usages:     []certV1beta1.KeyUsage{certV1beta1.UsageServerAuth, certV1beta1.UsageClientAuth, certV1beta1.UsageDigitalSignature, certV1beta1.UsageKeyAgreement},
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

func getKubernetesVersion(clientset kubernetes.Interface) (*VersionInfo, error) {
	v, err := clientset.Discovery().ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("failed to check k8s version: %v", err)
	}

	if v.Major != "1" {
		return nil, nil
	}

	// filter out a proceeding '+' from the minor version since openshift includes that.
	minor, err := strconv.Atoi(strings.TrimSuffix(v.Minor, "+"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse k8s minor version %s", v.Minor)
	}

	return &VersionInfo{
		Minor: minor,
	}, nil
}
