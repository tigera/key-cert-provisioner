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

package cfg

import (
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// Config holds parameters that are used during runtime.
type Config struct {
	CSRName             string
	EmptyDirLocation    string
	Signer              string
	CommonName          string
	EmailAddress        string
	PodIP               string
	KeyName             string
	CertName            string
	DNSNames            []string
	SignatureAlgorithm  string
	PrivateKeyAlgorithm string
	RegisterApiserver   bool
	AppName             string
}

// GetEnvOrDie convenience method for initializing env.
func GetEnvOrDie(env string) string {
	val := os.Getenv(env)
	if val == "" {
		log.Fatalf("environment variable %v cannot be empty", env)
	}
	return val
}

// GetConfigOrDie initializes the Config that this program relies on. It exists the program if expected variables are missing.
func GetConfigOrDie() *Config {
	dnsNames := strings.Split(os.Getenv("DNS_NAMES"), ",")
	if len(dnsNames) == 0 {
		log.Fatal("environment variable DNS_NAMES cannot be empty")
	}
	return &Config{
		CSRName:             fmt.Sprintf("%s:%s", GetEnvOrDie("POD_NAMESPACE"), GetEnvOrDie("POD_NAME")),
		SignatureAlgorithm:  os.Getenv("SIGNATURE_ALGORITHM"),
		Signer:              GetEnvOrDie("SIGNER"),
		CommonName:          GetEnvOrDie("COMMON_NAME"),
		EmailAddress:        os.Getenv("EMAIL_ADDRESS"),
		EmptyDirLocation:    GetEnvOrDie("CERTIFICATE_PATH"),
		KeyName:             GetEnvOrDie("KEY_NAME"),
		CertName:            GetEnvOrDie("CERT_NAME"),
		PodIP:               GetEnvOrDie("POD_IP"),
		AppName:             GetEnvOrDie("APP_NAME"),
		PrivateKeyAlgorithm: os.Getenv("KEY_ALGORITHM"),
		DNSNames:            dnsNames,
	}
}
