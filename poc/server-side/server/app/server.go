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

	fmt.Println(http.ListenAndServe(":9000", nil))
}
