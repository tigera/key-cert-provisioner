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

package main

import (
	"context"
	"flag"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/tigera/key-cert-provisioner/pkg/cfg"
	"github.com/tigera/key-cert-provisioner/pkg/k8s"
	"github.com/tigera/key-cert-provisioner/pkg/tls"
)

func main() {
	flag.Parse()
	log.SetLevel(log.InfoLevel)
	log.SetReportCaller(true)
	// Initiate (and validate) env variables
	config := cfg.GetConfigOrDie()
	ctx, cancel := context.WithTimeout(context.TODO(), config.TimeoutDuration)
	defer cancel()
	ch := make(chan int, 1)
	go func() {
		// Initiate REST restClient
		restClient, err := k8s.NewRestClient()
		if err != nil {
			log.WithError(err).Fatalf("Unable to create a kubernetes rest restClient")
		}

		csr, err := tls.CreateX509CSR(config)
		if err != nil {
			log.WithError(err).Fatalf("Unable to create x509 certificate request")
		}

		if err := k8s.SubmitCSR(ctx, config, restClient, csr); err != nil {
			log.WithError(err).Fatalf("Unable to submit a CSR")
		}

		if err := k8s.WatchCSR(ctx, restClient, config, csr); err != nil {
			log.WithError(err).Fatalf("Unable to watch CSR")
		}
		ch <- 0
	}()

	// Wait for the work to finish. If it takes too we crash-loop to improve the odds of the pod eventually getting up and running.
	select {
	case <-ch:
		log.Info("successfully obtained a certificate")
		ch <- 0
	case <-ctx.Done():
		log.Fatal("timeout expired, exiting program with exit code 1")
		os.Exit(1)
	}
}
