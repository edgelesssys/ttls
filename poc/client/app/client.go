package main

import (
	"fmt"
	"net/http"
)

func main() {
	resp, err := http.Get("http://localhost:9000")
	if err != nil {
		panic(err)
	}
	fmt.Println(resp)
}
