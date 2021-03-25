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

package k8s_test

import (
	"context"
	"fmt"
	"strconv"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/tigera/key-cert-provisioner/pkg/cfg"
	"github.com/tigera/key-cert-provisioner/pkg/k8s"
	"github.com/tigera/key-cert-provisioner/pkg/tls"

	certV1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/version"
	discoveryFake "k8s.io/client-go/discovery/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

var _ = Describe("Test Certificates", func() {
	ctx := context.Background()

	var (
		// Clients and configurations that will be initialized.
		config     *cfg.Config
		clientset  kubernetes.Interface
		tlsCsr     *tls.X509CSR
		restClient *k8s.RestClient

		// Variables that are set and tested.
		csrName = "calico-node:calico-node:12345"
		csrPem  = []byte("<this is a csr>")
		signer  = "example.com/signer"
	)

	BeforeEach(func() {
		clientset = fake.NewSimpleClientset()
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: strconv.Itoa(3),
			Minor: strconv.Itoa(2),
		}
		config = &cfg.Config{
			Signer:  signer,
			CSRName: csrName,
		}
		tlsCsr = &tls.X509CSR{
			CSR: csrPem,
		}
		restClient = &k8s.RestClient{
			APIRegistrationClient: nil,
			Clientset:             clientset,
			RestConfig:            nil,
		}
	})
	Context("Test submitting a CSR", func() {
		It("should list no CSRs when the suite starts", func() {
			By("verifying no CSRs are present yet")
			resp, err := clientset.CertificatesV1().CertificateSigningRequests().List(ctx, v1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(resp.Items).To(HaveLen(0))

			By("creating the CSRs are present yet")
			Expect(k8s.SubmitCSR(ctx, config, restClient, tlsCsr)).ToNot(HaveOccurred())

			By("Verifying the object exists with the right settings")
			csrs, err := clientset.CertificatesV1().CertificateSigningRequests().List(ctx, v1.ListOptions{})
			Expect(err).NotTo(HaveOccurred())
			Expect(csrs.Items).To(HaveLen(1))
			csr := csrs.Items[0]

			Expect(csr.Name).To(Equal(csrName))
			Expect(csr.Spec.Request).To(Equal(csrPem))
			Expect(csr.Spec.SignerName).To(Equal(signer))
			Expect(csr.Spec.Usages).To(ConsistOf(certV1.UsageServerAuth, certV1.UsageClientAuth, certV1.UsageDigitalSignature, certV1.UsageKeyAgreement))
		})
	})
})

var _ = Describe("Test get Kubernetes version", func() {
	var clientset kubernetes.Interface

	BeforeEach(func() {
		clientset = fake.NewSimpleClientset()
	})

	It("should return expected major and minor version when both version numbers are valid integers", func() {
		expectedMajor := 3
		expectedMinor := 22
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: strconv.Itoa(expectedMajor),
			Minor: strconv.Itoa(expectedMinor),
		}

		version, err := k8s.GetKubernetesVersion(clientset)
		Expect(err).NotTo(HaveOccurred())
		Expect(version.Major).To(Equal(expectedMajor))
		Expect(version.Minor).To(Equal(expectedMinor))
	})

	It("should return error when major version is invalid", func() {
		invalidMajor := "invalid_major_version"
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: invalidMajor,
			Minor: "19",
		}

		v, err := k8s.GetKubernetesVersion(clientset)
		Expect(v).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(fmt.Errorf("failed to parse k8s major version: %s", invalidMajor)))
	})

	It("should return error when minor version is invalid", func() {
		invalidMinor := "invalid_minor_version"
		clientset.Discovery().(*discoveryFake.FakeDiscovery).FakedServerVersion = &version.Info{
			Major: "1",
			Minor: invalidMinor,
		}

		v, err := k8s.GetKubernetesVersion(clientset)
		Expect(v).To(BeNil())
		Expect(err).To(HaveOccurred())
		Expect(err).To(Equal(fmt.Errorf("failed to parse k8s minor version: %s", invalidMinor)))
	})
})
