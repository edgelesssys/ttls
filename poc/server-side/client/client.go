package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	caCertPool := x509.NewCertPool()
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		panic(err)
	}
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		panic("Error reading CAcert")
	}

	cert, err := tls.LoadX509KeyPair("client.crt", "client.key")
	if err != nil {
		panic(err)
	}
	conf := &tls.Config{Certificates: []tls.Certificate{cert}, ClientCAs: caCertPool, RootCAs: caCertPool, ClientAuth: tls.RequireAndVerifyClientCert}

	transport := &http.Transport{TLSClientConfig: conf}
	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://localhost:9000")
	if err != nil {
		panic(err)
	}

	fmt.Println(resp)
}
