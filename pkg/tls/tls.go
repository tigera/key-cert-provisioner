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

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"net"

	"github.com/tigera/key-cert-provisioner/pkg/cfg"
)

type X509CSR struct {
	PrivateKey    interface{}
	PrivateKeyPEM []byte
	CSR           []byte
}

// CreateX509CSR creates a certificate signing request based on a configuration.
func CreateX509CSR(config *cfg.Config) (*X509CSR, error) {
	subj := pkix.Name{
		CommonName:         config.CommonName,
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Tigera"},
		OrganizationalUnit: []string{"Engineering"},
	}

	if config.EmailAddress != "" {
		subj.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(config.EmailAddress),
				},
			},
		}
	}

	// Cert does not need to function as a CA.
	val, err := asn1.Marshal(basicConstraints{false, -1})
	if err != nil {
		return nil, err
	}

	// step: generate a csr template
	csrTemplate := x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           config.DNSNames,
		IPAddresses:        []net.IP{net.ParseIP(config.PodIP)},
		SignatureAlgorithm: SignatureAlgorithm(config.SignatureAlgorithm),
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    val,
				Critical: true,
			},
		},
	}
	privateKey, privateKeyPem, err := GeneratePrivateKey(config.NewPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create private key: %w", err)
	}
	// step: generate the csr request
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create an x509 csr: %w", err)
	}
	return &X509CSR{
		PrivateKey:    privateKey,
		PrivateKeyPEM: privateKeyPem,
		CSR: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
		}),
	}, nil
}

// basicConstraints is a struct needed for creating a template.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// Create a private key based on the env variables.
// Default: 2048 bit.
func GeneratePrivateKey(algorithm string) (interface{}, []byte, error) {
	switch algorithm {
	case "RSAWithSize2048":
		return genRSA(2048)

	case "RSAWithSize4096":
		return genRSA(4096)

	case "RSAWithSize8192":
		return genRSA(8192)

	case "ECDSAWithCurve256":
		return genECDSA(elliptic.P256())

	case "ECDSAWithCurve384":
		return genECDSA(elliptic.P384())

	case "ECDSAWithCurve521":
		return genECDSA(elliptic.P521())

	default:
		return genRSA(2048)
	}
}

// genECDSA generates a private key.
func genECDSA(curve elliptic.Curve) (interface{}, []byte, error) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	byteArr, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: byteArr})
	return key, buf.Bytes(), err

}

// genRSA generates a private key.
func genRSA(size int) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, buf.Bytes(), err

}

// SignatureAlgorithm returns a x506 signature algorithm based on the env variables.
// Default: SHA256WithRSA
func SignatureAlgorithm(algorithm string) x509.SignatureAlgorithm {
	switch algorithm {

	case "SHA256WithRSA":
		return x509.SHA256WithRSA

	case "SHA384WithRSA":
		return x509.SHA384WithRSA

	case "SHA512WithRSA":
		return x509.SHA512WithRSA

	case "ECDSAWithSHA256":
		return x509.ECDSAWithSHA256

	case "ECDSAWithSHA384":
		return x509.ECDSAWithSHA384

	case "ECDSAWithSHA512":
		return x509.ECDSAWithSHA512

	default:
		return x509.SHA256WithRSA
	}
}
