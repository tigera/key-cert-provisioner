package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"time"

	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/goombaio/namegenerator"
)

var (
	masterURL  string
	kubeconfig string
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
	if secretLocation == "" {
		log.Fatalf("environment variable SECRET_LOCATION cannot be empty.")
	}
	privateKey, privateKeyPem, err := getPrivateKey()
	if err != nil {
		log.Fatalf("Unable to create private key: %w", err)
	}

	certV1Client := clientset.CertificatesV1beta1()
	seed := time.Now().UTC().UnixNano()
	nameGenerator := namegenerator.NewNameGenerator(seed)
	name := nameGenerator.Generate()

	log.Println(name)

	csrPem, err := createCSR(commonName, emailAddress, signatureAlgorithm, privateKey)
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta:   metaV1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metaV1.ObjectMeta{Name: name},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:    csrPem,
			SignerName: &signer,
			Usages:     []v1beta1.KeyUsage{v1beta1.UsageCodeSigning},
		},
	}
	if err != nil {
		log.Fatalf("Unable to create x509 certificate request: %w", err)
	}

	created, err := certV1Client.CertificateSigningRequests().Create(ctx, csr, metaV1.CreateOptions{})
	if err != nil {
		log.Fatal("crashed while trying to create Kubernetes certificate signing request", err)
	}
	log.Printf("Created CSR: %v", created)

	watchers, err := certV1Client.CertificateSigningRequests().Watch(ctx, metaV1.ListOptions{})

	ch := watchers.ResultChan()
	log.Printf("Watching CSR until it has been signed and approved: %v", name)
	for event := range ch {
		csr, ok := event.Object.(*v1beta1.CertificateSigningRequest)
		if !ok {
			log.Fatal("unexpected type in cert channel")
		}
		if csr.Name == name && csr.Status.Conditions != nil && csr.Status.Certificate != nil {
			approved := false
			for _, c := range csr.Status.Conditions {
				if c.Type == v1beta1.CertificateApproved && c.Status != v1.ConditionFalse {
					approved = true
					break
				}
			}
			if approved {
				log.Printf("the CSR has been issued, writing to secret: %v", secretLocation)
				secret := v1.Secret{Data: map[string][]byte{
					"cert.crt": csr.Status.Certificate,
					"key.key":  privateKeyPem,
				}}
				bytes, err := json.Marshal(secret)
				if err != nil {
					log.Fatal("unexpected error while writing secret")
				}
				err = ioutil.WriteFile(secretLocation, bytes, 0)
				if err != nil {
					log.Fatalf("error while writing to file: %w", err)
				}

				break
			}
		}
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "/home/rd/bzprofiles/kadm/.local/kubeconfig", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "127.0.0.1:8001", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}

//
// createCertificateAuthority generates a certificate authority request ready to be signed
//
func createCSR(cn, emailAddress string, signatureAlgorithm x509.SignatureAlgorithm, privateKey interface{}) ([]byte, error) {
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
	var key interface{}
	var err error

	switch os.Getenv("KEY_ALGORITHM") {
	case "RSAWithSize2048":
		key, err = rsa.GenerateKey(rand.Reader, 2048)
		break

	case "RSAWithSize4096":
		key, err = rsa.GenerateKey(rand.Reader, 4096)
		break

	case "RSAWithSize8192":
		key, err = rsa.GenerateKey(rand.Reader, 8192)
		break

	case "ECDSAWithCurve256":
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		break

	case "ECDSAWithCurve384":
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		break

	case "ECDSAWithCurve521":
		key, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		break

	default:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	}

	if err != nil {
		return nil, nil, err
	}
	privateKeyPem, err := x509.MarshalPKCS8PrivateKey(key)
	return key, privateKeyPem, err

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
		return x509.SHA512WithRSA
	}
}
