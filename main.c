#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define CLEARLENGTH 128

/* aes padding */
#define AES_BLOCK 16
int aes_padding(int size) {
    return size + AES_BLOCK - (size%AES_BLOCK);
}

void load_pub_key(const char *path, EVP_PKEY **key) {
    FILE *rsa_key_file = fopen(path, "r");
    if (rsa_key_file) {
        if (!PEM_read_PUBKEY(rsa_key_file, key, NULL, NULL)) {
            fprintf(stderr, "Error loading Public Key File.\n");
        }
        fclose(rsa_key_file);
    }
}

void load_pri_key(const char *path, EVP_PKEY **key) {
    FILE *rsa_key_file = fopen(path, "r");
	unsigned char buf[1024] = {'\0'};
    struct stat st;
    if(stat(path, &st) != 0) {
        fprintf(stderr, "der key is not avaliable.\n");
        exit -1;
    }
    BIO *b;

    if (rsa_key_file) {
		/* convert pri key from DER to RSA */
		if (st.st_size == fread(buf, sizeof(unsigned char), st.st_size, rsa_key_file)) {
			b = BIO_new_mem_buf(buf, st.st_size);
			*key = d2i_PrivateKey_bio(b, key);
			BIO_free_all(b);
		}		
        fclose(rsa_key_file);
    }
}

void encrypt_seal(const EVP_CIPHER *cipher,
        unsigned char **ek /*OUT*/, int *ekl /*OUT*/, unsigned char **iv /*OUT*/,
        EVP_PKEY **pubk, int npubk,
        unsigned char *data /*IN*/, int dlen /*IN*/,
        unsigned char **out /*OUT*/, int *olen /*OUT*/) {

    int ulen = 0;
    int flen = 0;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_SealInit(&ctx, cipher, ek, ekl, *iv, pubk, npubk)) {
        fprintf(stderr, "EVP_SealInit Failed\n");
        return;
    }

    if (!EVP_SealUpdate(&ctx, *out, &ulen, data, dlen)) {
        fprintf(stderr, "EVP_SealUpdate Failed\n");
        return;
    }
    *olen = ulen;

    if (!EVP_SealFinal(&ctx, *out + ulen, &flen)) {
        fprintf(stderr, "EVP_SealFinal Failed\n");
        return;
    }

    *olen += flen;
    EVP_CIPHER_CTX_cleanup(&ctx);
}


void decrypt_seal(const EVP_CIPHER *cipher,
        unsigned char *ek /*IN*/, int ekl /*IN*/, unsigned char *iv /*IN*/,
        EVP_PKEY *prik, unsigned char *data /*IN*/, int dlen /*IN*/,
        unsigned char **out /*OUT*/, int *olen /*OUT*/) {

    int ulen = 0;
    int flen = 0;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    if (!EVP_OpenInit(&ctx, cipher, ek, ekl, iv, prik)) {
        fprintf(stderr, "EVP_OpenInit Failed\n");
        return;
    }

    if (!EVP_OpenUpdate(&ctx, *out, &ulen, data, dlen)) {
        fprintf(stderr, "EVP_OpenUpdate Failed\n");
        return;
    }
    *olen = ulen;

    if (!EVP_OpenFinal(&ctx, *out + ulen, &flen)) {
        fprintf(stderr, "EVP_OpenFinal Failed\n");
        return;
    }

    *olen += flen;
    EVP_CIPHER_CTX_cleanup(&ctx);
}

void hexdump(void *data, int size)
{
    /* dumps size bytes of *data to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};
    for(n=1;n<=size;n++) {
        if (n%16 == 1) {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
               ((unsigned int)p-(unsigned int)data) );
        }
            
        c = *p;
        if (isprint(c) == 0) {
        //if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0) { 
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if(n%8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

int main() {
	/* use RSA encrypt, you need to save ek and iv for decrypt */
    unsigned char *ek = NULL;
    unsigned char *iv = NULL;
    unsigned char *encryptedText = NULL;
    unsigned char *decryptedText = NULL;
	unsigned char *clearInput = NULL;
    int encryptedTextLength = -1, encryptedOutputLength = -1;
    int decryptedTextLength = -1, decryptedOutputLength = -1;
    int ekSize = 0, ivSize = 0, totalSize = 0;
	int i = 0;
    EVP_PKEY *pubk = NULL;
    EVP_PKEY *prik = NULL;

	/* start up encrypt engine */
    OpenSSL_add_all_algorithms();
    load_pub_key("public.key", &pubk);

    ekSize = EVP_PKEY_size(pubk);
    ivSize = EVP_MAX_IV_LENGTH;
    ek = malloc(ekSize);
    iv = malloc(ivSize);
	clearInput = calloc(CLEARLENGTH, sizeof(unsigned char));
    encryptedText = calloc(aes_padding(CLEARLENGTH), sizeof(unsigned char));

	/* generate test input */
	for(i = 0; i < CLEARLENGTH; ++i)
		clearInput[i] = (unsigned char) i;

	/* dump test input */
	printf("dump test input data:\n");
	hexdump(clearInput, CLEARLENGTH);	
	printf("\n");
    encrypt_seal(EVP_aes_256_cbc(),
				&ek, 
				&encryptedTextLength,
				&iv,
				&pubk,
				1,
				clearInput,
				CLEARLENGTH,
				&encryptedText,
				&encryptedOutputLength);

	printf("dump encrypted input data:\n");
    hexdump(encryptedText, encryptedOutputLength);
	printf("\n");

    decryptedText = calloc(CLEARLENGTH, sizeof(unsigned char));
    load_pri_key("der_private.key", &prik);
    decrypt_seal(EVP_aes_256_cbc(),
				ek,
				128, // ek size
				iv,
				prik,
				encryptedText,
				encryptedOutputLength,
				&decryptedText,
				&decryptedTextLength);

	printf("dump decrypted input data:\n");
	hexdump(decryptedText, decryptedTextLength);
	printf("\n");

	if(clearInput)    free(clearInput);
	if(encryptedText) free(encryptedText);
	return 0;
}


