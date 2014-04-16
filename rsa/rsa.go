package RSA

/*
	#cgo LDFLAGS: -lssl -lcrypto
	#include <openssl/rsa.h>
	#include <openssl/engine.h>
	#include <openssl/pem.h>
	#include <openssl/err.h>
	#include <stdio.h>
	#include <stdlib.h>

 	RSA* rsa_read_pem_public(char* pem){
 		FILE * fp = fopen(pem,"r");
 		if(fp == NULL){
			return NULL;
 		}

 		RSA * public_key = RSA_new();

 		if (!PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL)){
			RSA_free(public_key);
			return NULL;
		}
		return public_key;
 	}

 	RSA* rsa_read_pem_private(char* pem){
 		FILE * fp = fopen(pem,"r");
 		if(fp == NULL){
			return NULL;
 		}
 		RSA * private_key = RSA_new();

 		if (!PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL)){
			RSA_free(private_key);
			return NULL;
		}
		return private_key;
 	}

	int rsa_private_encrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
		RSA* private_key = rsa_read_pem_private(pem);
		if(!private_key){
			return -1;
		}
		*to = (char*)malloc(sizeof(char) * RSA_size(private_key));
		return RSA_private_encrypt(fromSize,from,(unsigned char *)*to,private_key,padding);
	}

	int rsa_public_decrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
		RSA* public_key = rsa_read_pem_public(pem);
		if(!public_key){
			return -1;
		}
		*to = (char*)malloc(sizeof(char) * RSA_size(public_key));
		return RSA_public_decrypt(fromSize,from,(unsigned char *)*to,public_key,padding);
	}
*/
import "C"
import "unsafe"
import "fmt"

const (
	RSA_PKCS1_PADDING = C.RSA_PKCS1_PADDING
	RSA_NO_PADDING    = C.RSA_NO_PADDING
)

func PublicDecrypt(from []byte, pem string, padding int) ([]byte, error) {
	var to *C.char = nil

	if n := C.rsa_public_decrypt(C.int(len(from)),
		(*C.uchar)(unsafe.Pointer(&from[0])),
		//(*C.uchar)(unsafe.Pointer(&to[0])),
		(**C.char)(unsafe.Pointer(&to)),
		C.CString(pem),
		C.int(padding)); n < 0 {
		return nil, fmt.Errorf("PublicDecrypt failed")
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}

func PrivateEncrypt(from []byte, pem string, padding int) ([]byte, error) {
	var to *C.char = nil

	if n := C.rsa_private_encrypt(C.int(len(from)),
		(*C.uchar)(unsafe.Pointer(&from[0])),
		(**C.char)(unsafe.Pointer(&to)),
		//(*C.uchar)(unsafe.Pointer(&to[0])),
		C.CString(pem),
		C.int(padding)); n < 0 {
		return nil, fmt.Errorf("PrivateEncrypt failed")
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}
