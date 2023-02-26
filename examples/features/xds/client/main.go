/*
 *
 * Copyright 2020 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

// Binary main implements a client for Greeter service using gRPC's client-side
// support for xDS APIs.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	//"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/credentials/insecure"
	xdscreds "google.golang.org/grpc/credentials/xds"
	pb "google.golang.org/grpc/examples/helloworld/helloworld"

	_ "google.golang.org/grpc/xds" // To install the xds resolvers and balancers.
	"google.golang.org/grpc/xds/bootstrap"
)

var (
	target   = flag.String("target", "xds:///localhost:50051", "uri of the Greeter Server, e.g. 'xds:///helloworld-service:8080'")
	name     = flag.String("name", "world", "name you wished to be greeted by the server")
	xdsCreds = flag.Bool("xds_creds", false, "whether the server should use xDS APIs to receive security configuration")
	upstream = flag.String("service", "", "service name that will go into HTTP request header")
)

// TLSXdsCredsBundle implements the credentials.Bundle interface, it can be used to secure the trasport with xDS Server.
type TLSXdsCredsBundle struct {
	CABundleFile string `json:"ca_bundle_file,omitempty"`
	KeyFile string `json:"key_file,omitempty"`
	CertFile string `json:"cert_file,omitempty"`
}

func (tb *TLSXdsCredsBundle) PerRPCCredentials() credentials.PerRPCCredentials {
	return nil
}

func (tb *TLSXdsCredsBundle) TransportCredentials() credentials.TransportCredentials {
	caCerts, err := x509.SystemCertPool()
	if err != nil {
		log.Fatalf("Unable to load system cert pool: %v\n", err)
	}

    ca, err := os.ReadFile(tb.CABundleFile)
    if err != nil {
        log.Fatalf("Failed to read %q: %+v\n", tb.CABundleFile, err)
    }

    if !caCerts.AppendCertsFromPEM(ca) {
        log.Fatalf("Could not decode CA bundle from %q: %+v\n", tb.CABundleFile, err)
    }

    cert, err := tls.LoadX509KeyPair(tb.CertFile, tb.KeyFile)
    if err != nil {
        log.Fatalf("Failed to read X509 key pair from %q and %q: %+v", tb.CertFile, tb.KeyFile, err)
    }

    cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
    if err != nil {
        log.Fatalf("Failed to parse application certs: %+v", err)
    }

    _, err = cert.Leaf.Verify(x509.VerifyOptions{
        Roots:       caCerts,
        CurrentTime: time.Now(),
    })
    if err != nil {
        log.Fatalf("Invalid application certs: %+v", err)
    }

    return credentials.NewTLS(&tls.Config{
         Certificates: []tls.Certificate{cert},
         RootCAs:      caCerts,
         NextProtos:   []string{"h2"},
    })
}

func (tb *TLSXdsCredsBundle) NewWithMode(mode string) (credentials.Bundle, error) {
	return &TLSXdsCredsBundle{tb.CABundleFile, tb.CertFile, tb.KeyFile}, nil
}

// TLSXdsCredsBuilder is the factory of TLSXdsCredsBundle.
type TLSXdsCredsBuilder struct {}

func (tcb *TLSXdsCredsBuilder) Build(config json.RawMessage) (credentials.Bundle, error) {
	tb := TLSXdsCredsBundle{}
	if err := json.Unmarshal([]byte(config), &tb); err != nil {
		log.Printf("Unable to unmarshal TLSXdsCredsBuilder JSON config %v, err=%v\n", fmt.Sprintf("%s", config), err);
		return nil, err
	}

	return &tb, nil
}

func (tcb *TLSXdsCredsBuilder) Name() string {
	return "TLSXdsCredsBuilder"
}

func init() {
	bootstrap.RegisterCredentials(&TLSXdsCredsBuilder{})
}

func main() {
	flag.Parse()

	if !strings.HasPrefix(*target, "xds:///") {
		log.Fatalf("-target must use a URI with scheme set to 'xds'")
	}

	creds := insecure.NewCredentials()
	if *xdsCreds {
		log.Println("Using xDS credentials...")
		var err error
		if creds, err = xdscreds.NewClientCredentials(xdscreds.ClientOptions{FallbackCreds: insecure.NewCredentials()}); err != nil {
			log.Fatalf("failed to create client-side xDS credentials: %v", err)
		}
	}
	opt := []grpc.DialOption{}
	opt = append(opt, grpc.WithAuthority(*upstream))
	opt = append(opt, grpc.WithTransportCredentials(creds))
	conn, err := grpc.Dial(*target, opt...)
	if err != nil {
		log.Fatalf("grpc.Dial(%s) failed: %v", *target, err)
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := pb.NewGreeterClient(conn)
	r, err := c.SayHello(ctx, &pb.HelloRequest{Name: *name})
	if err != nil {
		log.Printf("Error: could not greet: %v", err)
	}
	log.Printf("Greeting: %s", r.GetMessage())
}
