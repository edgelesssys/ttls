package main

import (
	"fmt"
	"net/http"
)

func hello(w http.ResponseWriter, req *http.Request) {

	fmt.Fprintf(w, "hello\n")
}

func main() {

	http.HandleFunc("/", hello)

	http.ListenAndServeTLS(":9000", "cert.pem", "key.pem", nil)
}
