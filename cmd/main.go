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
	"net"
	"os"
	"path"
	"strings"

	"k8s.io/api/certificates/v1beta1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	apiregistrationv1beta1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1beta1"
	v1beta12 "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset/typed/apiregistration/v1beta1"
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
	aapiVersionGroup   = "v3.projectcalico.org"
)

type config struct {
	csrName            string
	signer             string
	commonName         string
	emailAddress       string
	secretLocation     string
	podIP              string
	keyName            string
	certName           string
	dnsNames           []string
	signatureAlgorithm x509.SignatureAlgorithm
	privateKey         interface{}
	privateKeyPem      []byte
	registerApiserver  bool
}

// getEnvOrDie convenience method for initializing env.
func getEnvOrDie(env string) string {
	val := os.Getenv(env)
	if val == "" {
		log.Panicf("environment variable %v cannot be empty", env)
	}
	return val
}

// getConfig initializes the config that this program relies on.
func getConfig() config {
	cfg := config{
		csrName:            fmt.Sprintf("%s:%s:%s", getEnvOrDie("POD_NAMESPACE"), getEnvOrDie("POD_NAME"), string([]rune(getEnvOrDie("POD_UID"))[0:6])),
		signatureAlgorithm: getSignatureAlgorithm(),
		signer:             getEnvOrDie("SIGNER"),
		commonName:         getEnvOrDie("COMMON_NAME"),
		emailAddress:       os.Getenv("EMAIL_ADDRESS"),
		secretLocation:     getEnvOrDie("SECRET_LOCATION"),
		keyName:            getEnvOrDie("KEY_NAME"),
		certName:           getEnvOrDie("CERT_NAME"),
		registerApiserver:  os.Getenv("REGISTER_APISERVER") == "true",
		podIP:              getEnvOrDie("POD_IP"),
	}
	privateKey, privateKeyPem, err := getPrivateKey()
	if err != nil {
		log.Fatalf("Unable to create private key: %w", err)
	}
	cfg.privateKey = privateKey
	cfg.privateKeyPem = privateKeyPem
	cfg.dnsNames = strings.Split(os.Getenv("DNS_NAMES"), ",")
	if len(cfg.dnsNames) == 0 {
		log.Fatal("environment variable DNS_NAMES cannot be empty")
	}
	return cfg
}

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// Initiate necessary variables.
	ctx := context.Background()

	// Initiate (and validate) env variables
	cfg := getConfig()

	// Initiate REST client
	restfg, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}
	clientset, err := kubernetes.NewForConfig(restfg)
	if err != nil {
		panic(err.Error())
	}

	csrPem, err := createCSR(cfg)
	csr := &v1beta1.CertificateSigningRequest{
		TypeMeta:   metav1.TypeMeta{Kind: "CertificateSigningRequest", APIVersion: "certificates.k8s.io/v1beta1"},
		ObjectMeta: metav1.ObjectMeta{Name: cfg.csrName},
		Spec: v1beta1.CertificateSigningRequestSpec{
			Request:    csrPem,
			SignerName: &cfg.signer,
			Usages:     []v1beta1.KeyUsage{v1beta1.UsageServerAuth, v1beta1.UsageDigitalSignature, v1beta1.UsageKeyAgreement},
		},
	}
	if err != nil {
		log.Fatalf("Unable to create x509 certificate request: %w", err)
	}

	created, err := clientset.CertificatesV1beta1().CertificateSigningRequests().Create(ctx, csr, metav1.CreateOptions{})
	if err != nil && !errors.IsAlreadyExists(err) {
		log.Fatal("crashed while trying to create Kubernetes certificate signing request", err)
	}
	log.Printf("created CSR: %v", created)

	watchCSR(clientset, restfg, ctx, cfg)
}

func watchCSR(clientset *kubernetes.Clientset, restfg *rest.Config, ctx context.Context, cfg config) {
	watchers, err := clientset.CertificatesV1beta1().CertificateSigningRequests().Watch(ctx, metav1.ListOptions{})
	ch := watchers.ResultChan()
	log.Printf("watching CSR until it has been signed and approved: %v", cfg.csrName)
	for event := range ch {
		chcsr, ok := event.Object.(*v1beta1.CertificateSigningRequest)
		if !ok {
			continue
		}
		if chcsr.Name == cfg.csrName && chcsr.Status.Conditions != nil && chcsr.Status.Certificate != nil {
			approved := false
			for _, c := range chcsr.Status.Conditions {
				if c.Type == v1beta1.CertificateApproved && c.Status != v1.ConditionFalse {
					approved = true
					break
				}
			}
			if approved {
				log.Printf("the CSR has been signed and approved, writing to secret: %v", cfg.secretLocation)

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(cfg.secretLocation, cfg.certName), chcsr.Status.Certificate, os.FileMode(0744))
				if err != nil {
					log.Fatalf("error while writing to file: %w", err)
				}

				// Give other users read permission to this file.
				err = ioutil.WriteFile(path.Join(cfg.secretLocation, cfg.keyName), cfg.privateKeyPem, os.FileMode(0744))
				if err != nil {
					log.Fatalf("error while writing to file: %w", err)
				}

				if cfg.registerApiserver {
					registerApiServer(ctx, restfg, chcsr)
				}
				break
			}
		}
	}
}

// registerApiServer creates a registration for this pod to run as an aggregated apiserver.
func registerApiServer(ctx context.Context, restfg *rest.Config, chcsr *v1beta1.CertificateSigningRequest) {
	apiregistrationClient, err := v1beta12.NewForConfig(restfg)
	if err != nil {
		log.Panicf("Unable to create apiregistrationClient: %w", err)
	}
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
			CABundle: chcsr.Status.Certificate,
		},
	}

	existing, err := apiregistrationClient.APIServices().Get(ctx, aapiVersionGroup, metav1.GetOptions{})
	if err == nil {
		// It exists already, so we must update it.
		existing.Spec = apiService.Spec
		_, err = apiregistrationClient.APIServices().Update(ctx, existing, metav1.UpdateOptions{})
	} else if errors.IsNotFound(err) {
		// Create the apiservice
		_, err = apiregistrationClient.APIServices().Create(ctx, apiService, metav1.CreateOptions{})
	}

	if err != nil {
		log.Fatalf("error during api service registration for: %w", err)
	}
}

func init() {
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to a kubeconfig. Only required if out-of-cluster.")
	flag.StringVar(&masterURL, "master", "", "The address of the Kubernetes API server. Overrides any value in kubeconfig. Only required if out-of-cluster.")
}

// createCSR generates a certificate signing request based on the pod's properties.
func createCSR(cfg config) ([]byte, error) {
	subj := pkix.Name{
		CommonName:         cfg.commonName,
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
		Organization:       []string{"Tigera"},
		OrganizationalUnit: []string{"Engineering"},
	}

	if cfg.emailAddress != "" {
		subj.ExtraNames = []pkix.AttributeTypeAndValue{
			{
				Type: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1},
				Value: asn1.RawValue{
					Tag:   asn1.TagIA5String,
					Bytes: []byte(cfg.emailAddress),
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
		DNSNames:           cfg.dnsNames,
		IPAddresses:        []net.IP{net.ParseIP(cfg.podIP)},
		SignatureAlgorithm: cfg.signatureAlgorithm,
		ExtraExtensions: []pkix.Extension{
			{
				Id:       asn1.ObjectIdentifier{2, 5, 29, 19},
				Value:    val,
				Critical: true,
			},
		},
	}
	// step: generate the csr request
	csrCertificate, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, cfg.privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE REQUEST", Bytes: csrCertificate,
	}), nil
}

// basicConstraints is a struct needed for creating a template.
type basicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// Create a private key based on the env variables.
// Default: 2048 bit.
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

// getSignatureAlgorithm returns a x506 signature algorithm based on the env variables.
// Default: SHA256WithRSA
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
