package main

import "os"
import "log"
import "io/ioutil"
import "github.com/sonrac/rsa/rsa"
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

	brsa, e := rsa.PrivateEncrypt(b, "./private.pem", rsa.RSA_PKCS1_PADDING, "")
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

	brsaProtected, e := rsa.PrivateEncrypt(b, "./sigsso_private.key", rsa.RSA_PKCS1_PADDING, "123456789")
	if e != nil {
		fmt.Printf("%s\n", e.Error())
		return
	}
	ioutil.WriteFile("./sigsso_public.key", brsaProtected, os.ModePerm)

	bufProtected, e := rsa.PublicDecrypt(brsa, "./sigsso_public.key", rsa.RSA_PKCS1_PADDING)
	if e == nil {
		fmt.Printf("Decrypt: %s", string(bufProtected))
	} else {
		fmt.Printf("%s\n", e.Error())
		return
	}
}
