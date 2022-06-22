package main

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	caKeyFile, err := ioutil.ReadFile("root.key")
	if err != nil {
		log.Fatal(err)
	}
	caKey, err := x509.ParseECPrivateKey(caKeyFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(caKey.D)
}
