//
// Created by jiaxv on 2022/9/25.
//

#ifndef ACARS_CRYPT_CRYPTO_H
#define ACARS_CRYPT_CRYPTO_H

#define DEFAULT_LENGTH  512
#define KEY_LEN 16
#define IV_LEN 16
#define SYNKEY_LEN 16

typedef struct sm4_entity{
    int key_len;
    int plain_len;
    int cipher_len;
    uint8_t * key;
    uint8_t * iv;
    uint8_t * plain;
    uint8_t * plain_2;
    uint8_t * cipher;
}ce;

typedef struct sign_entity{
    char * filepath;
    char * pubpath;
    char * pripath;
    char * capath;
    char * capasswd;
    char * passwd;
    char * country;
    char * locality;
    char * province;
    char * organization;
    char * org_unit;
    char * common_name;
}se;

int setIv(uint8_t * );
int sm4_encrypt_CBC(ce * );
int sm4_decrypt_CBC(ce * );
static int set_x509_name(uint8_t * , size_t * , size_t , se * );
static int test_x509_cert_get(const uint8_t * , size_t , SM2_KEY * );
int getSign(char * , uint8_t * , size_t * , uint8_t * , size_t , char * );
int verifySign(char * , uint8_t * , size_t , uint8_t * , size_t );
int test_key(se * , SM2_KEY , size_t);
int getCertWith64(char *, uint8_t *, size_t * );
int savePrivateKey(SM2_KEY , se* , size_t );
int loadCAPrivateKey(se * , SM2_KEY * );
int test_x509_cert(se*);
int verifyCert(char * , uint8_t * , size_t );
void getRandomSymKey(uint8_t * );
int encryptRandomSymKey(uint8_t * , uint8_t * , size_t , uint8_t * , size_t * );
int decryptRandomSymKey(char * , uint8_t *, size_t , uint8_t * , size_t * );


#endif //ACARS_CRYPT_CRYPTO_H
