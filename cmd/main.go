package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	v1beta12 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1beta1"

	"k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
)

var (
	masterURL  string
	kubeconfig string
)

const (
	// Constants for creating the tigera-apiserver
	apiServerNamespace = "tigera-system"
	apiServiceName     = "tigera-api"
	calicoAPIGroup     = "projectcalico.org"
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	ctx := context.Background()
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}

	// Initiate necessary variables.
	signatureAlgorithm := getSignatureAlgorithm()
	signer := os.Getenv("SIGNER")
	commonName := os.Getenv("COMMON_NAME")
	emailAddress := os.Getenv("EMAIL_ADDRESS")
	secretLocation := os.Getenv("SECRET_LOCATION")
	keyName := os.Getenv("KEY_NAME")
	podIP := os.Getenv("POD_IP")
	if keyName == "" {
		keyName = "key.key"
	}
	certName := os.Getenv("CERT_NAME")
	if certName == "" {
		certName = "cert.crt"
	}
	registerApiserver := os.Getenv("REGISTER_APISERVER") == "true"
	if secretLocation == "" {
		log.Fatalf("environment variable SECRET_LOCATION cannot be empty.")
	}
	privateKey, privateKeyPem, err := getPrivateKey()
	if err != nil {
		log.Fatalf("Unable to create private key: %w", err)
	}

	certV1Client := clientset.CertificatesV1beta1()
	name := fmt.Sprintf("%s-%s-%s", os.Getenv("POD_NAMESPACE"), os.Getenv("POD_NAME"), string([]rune(os.Getenv("POD_UID"))[0:6]))

	log.Println(name)

	csrPem, err := createCSR(commonName, emailAddress, podIP, signatureAlgorithm, privateKey)
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta:   metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:    csrPem,
			SignerName: &signer,
			Usages:     []v1beta1.KeyUsage{v1beta1.UsageCodeSigning},
		},
	}
	if err != nil {
		log.Fatalf("Unable to create x509 certificate request: %w", err)
	}

	created, err := certV1Client.CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil {
		log.Fatal("crashed while trying to create Kubernetes certificate signing request", err)
	}
	log.Printf("Created CSR: %v", created)

	watchers, err := certV1Client.CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	ch := watchers.ResultChan()
	log.Printf("Watching CSR until it has been signed and approved: %v", name)
	for event := range ch {
		chcsr, ok := event.Object.(*v1beta1.CertificateSigningRequest)
		if !ok {
			log.Fatal("unexpected type in cert channel")
		}
		if chcsr.Name == name && chcsr.Status.Conditions != nil && chcsr.Status.Certificate != nil {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				if c.Type == v1beta1.CertificateApproved && c.Status != v1.ConditionFalse {
					approved = true
					break
				}
			}
			if approved {
				log.Printf("the CSR has been issued, writing to secret: %v", secretLocation)

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(secretLocation, certName), chcsr.Status.Certificate, os.FileMode(0744))
				if err != nil {
					log.Fatalf("error while writing to file: %w", err)
				}

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(secretLocation, keyName), privateKeyPem, os.FileMode(0744))
				if err != nil {
					log.Fatalf("error while writing to file: %w", err)
				}

				if registerApiserver {
					// Create a registration for this pod to run as an apiserver.
					apiregistrationClient, err := v1beta12.NewForConfig(config)
					if err != nil {
						log.Panicf("Unable to create apiregistrationClient: %w", err)
					}

					_, err = apiregistrationClient.APIServices().Create(ctx, &apiregistrationv1beta1.APIService{
						TypeMeta: metav1.TypeMeta{Kind: "APIService", APIVersion: "apiregistration.k8s.io/v1beta1"},
						ObjectMeta: metav1.ObjectMeta{
							Name: "v3.projectcalico.org",
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
							CABundle: chcsr.Status.Certificate,
						},
					}, metav1.CreateOptions{})

					if err != nil {
						log.Fatalf("error creating an api registration for the apiserver: %w", err)
					}

				}
				break
			}
		}
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}

//
// createCertificateAuthority generates a certificate authority request ready to be signed
//
func createCSR(cn, emailAddress, podIP string, signatureAlgorithm x509.SignatureAlgorithm, privateKey interface{}) ([]byte, error) {
	subj := pkix.Name{
		CommonName:         cn,
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Tigera"},
		OrganizationalUnit: []string{"Engineering"},
	}

	if emailAddress != "" {
		subj.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(emailAddress),
				},
			},
		}
	}

	// Cert does not need to function as a CA.
	type basicConstraints struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}

	val, err := asn1.Marshal(basicConstraints{false, -1})
	if err != nil {
		return nil, err
	}

	// step: generate a csr template
	var csrTemplate = x509.CertificateRequest{
		Subject:            subj,
		DNSNames:           []string{cn, podIP},
		SignatureAlgorithm: signatureAlgorithm,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    val,
				Critical: true,
			},
		},
	}
	// step: generate the csr request
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	}), nil
}

func getPrivateKey() (interface{}, []byte, error) {

	switch os.Getenv("KEY_ALGORITHM") {
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

func genRSA(size int) (*rsa.PrivateKey, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return nil, nil, err
	}
	buf := bytes.NewBuffer([]byte{})
	err = pem.Encode(buf, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, buf.Bytes(), err

}

func getSignatureAlgorithm() x509.SignatureAlgorithm {
	switch os.Getenv("SIGNATURE_ALGORITHM") {

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
