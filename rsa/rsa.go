package rsa

/*
	#cgo CFLAGS: -I/usr/local/opt/openssl/include
	#cgo LDFLAGS: -L/usr/include/openssl -Lmy/library/src -lcrypto
	#include <openssl/rsa.h>
	#include <openssl/engine.h>
	#include <openssl/pem.h>
	#include <openssl/err.h>
	#include <stdio.h>
	#include <stdlib.h>
	#include <string.h>

	char last_error_string[2048] = {0};

	RSA* get_rsa_from_public_key(char * pem)
	{
		RSA* RSA = RSA_new();

		BIO* bio = BIO_new(BIO_s_mem());
		int len = BIO_write(bio, pem, strlen(pem));
		EVP_PKEY* evp_key = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
		RSA = EVP_PKEY_get1_RSA(evp_key);

		return RSA;
	}

	RSA* get_rsa_from_private_key(char * pem, char * password)
	{
		RSA* RSA = RSA_new();

		BIO* bio = BIO_new(BIO_s_mem());
		int len = BIO_write(bio, pem, strlen(pem));
		RSA = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
		//RSA = PEM_read_bio_RSAPrivateKey(bio, NULL, (unsigned char*) password, NULL);
		//RSA = EVP_PKEY_get1_RSA(evp_key);

		return RSA;
	}

 	RSA* rsa_read_pem_public(char* pem){
 		FILE * fp = fopen(pem,"r");
 		if(fp == NULL){
 			return get_rsa_from_public_key(pem);
 			snprintf(last_error_string,sizeof(last_error_string),"open \"%s\" failed",pem);
			return NULL;
 		}

 		RSA * public_key = RSA_new();

 		if (!PEM_read_RSA_PUBKEY(fp, &public_key, NULL, NULL)){
 			snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
			RSA_free(public_key);
			return NULL;
		}
		return public_key;
 	}

 	RSA* rsa_read_pem_private(char* pem, char * password){
 		FILE * fp = fopen(pem,"r");
 		if(fp == NULL){
 			if (NULL == get_rsa_from_private_key(pem, password)) {
				snprintf(last_error_string,sizeof(last_error_string),"open \"%s\" failed",pem);
				return NULL;
			}
 		}
 		RSA * private_key = RSA_new();

 		//if (!PEM_read_RSAPrivateKey(fp, &private_key, (unsigned char*)password, NULL)){
 		if (!PEM_read_RSAPrivateKey(fp, &private_key, NULL, NULL)){
 			snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
			RSA_free(private_key);
			return NULL;
		}
		return private_key;
 	}

	int rsa_private_encrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding, char* password){
		RSA* private_key = rsa_read_pem_private(pem, password);
		if(!private_key){
			return -1;
		}
		*to = (char*)malloc(sizeof(char) * RSA_size(private_key));
		int n = RSA_private_encrypt(fromSize,from,(unsigned char *)*to,private_key,padding);
		if (n == -1){
 			snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
		}
		RSA_free(private_key);
		return n;
	}

	int rsa_public_decrypt(int fromSize,unsigned char *from,char** to, char* pem, int padding){
		RSA* public_key = rsa_read_pem_public(pem);
		if(!public_key){
			return -1;
		}
		*to = (char*)malloc(sizeof(char) * RSA_size(public_key));
		int n = RSA_public_decrypt(fromSize,from,(unsigned char *)*to,public_key,padding);
		if (n == -1){
 			snprintf(last_error_string,sizeof(last_error_string),"%s",ERR_error_string(ERR_get_error(),NULL));
		}
		RSA_free(public_key);
		return n;

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
		return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}

func PrivateEncrypt(from []byte, pem string, padding int, password string) ([]byte, error) {
	var to *C.char = nil

	if n := C.rsa_private_encrypt(C.int(len(from)),
		(*C.uchar)(unsafe.Pointer(&from[0])),
		(**C.char)(unsafe.Pointer(&to)),
		//(*C.uchar)(unsafe.Pointer(&to[0])),
		C.CString(pem),
		C.int(padding),
		C.CString(password)); n < 0 {
		return nil, fmt.Errorf("%s", C.GoString(&C.last_error_string[0]))
	} else {
		m := C.GoBytes(unsafe.Pointer(to), n)
		C.free(unsafe.Pointer(to))
		return m, nil
	}
}

func Destroy() {
	C.ERR_clear_error()
}

func init() {
	C.ERR_load_ERR_strings()
}
