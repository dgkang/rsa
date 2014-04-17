package main

import "os"
import "log"
import "io/ioutil"
import "github.com/dgkang/rsa/rsa"
import "fmt"

func main() {
	file, err := os.Open("./test.txt")
	if err != nil {
		log.Fatal(err)
	}
	b, e := ioutil.ReadAll(file)
	if e != nil {
		log.Fatal(e)
	}

	brsa, e := rsa.PrivateEncrypt(b, "./private.pem", rsa.RSA_PKCS1_PADDING)
	if e != nil {
		fmt.Printf("%s\n", e.Error())
		return
	}
	ioutil.WriteFile("./public.rsa", brsa, os.ModePerm)

	buf, e := rsa.PublicDecrypt(brsa, "./public.pem", rsa.RSA_PKCS1_PADDING)
	if e == nil {
		fmt.Printf("Decrypt: %s", string(buf))
	} else {
		fmt.Printf("%s\n", e.Error())
		return
	}
}
