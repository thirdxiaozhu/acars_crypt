#include <stdio.h>
#include <gmssl/sm4.h>
#include <gmssl/sm2.h>
#include <gmssl/error.h>
#include <gmssl/rand.h>
#include <gmssl/oid.h>
#include <gmssl/x509_alg.h>
#include <gmssl/x509.h>
#include "Crypto.h"

int setIv(uint8_t * iv){
    rand_bytes(iv, IV_LEN);
}

int sm4_encrypt_CBC(ce * entity){
    SM4_KEY sm4_key;

    sm4_set_encrypt_key(&sm4_key, entity->key);
    sm4_cbc_encrypt(&sm4_key, entity->iv, entity->plain, entity->cipher_len/16, entity->cipher);

    sm4_set_decrypt_key(&sm4_key, entity->key);
    sm4_cbc_decrypt(&sm4_key, entity->iv, entity->cipher, entity->cipher_len/16, entity->plain_2);

    return 0;
}

int sm4_decrypt_CBC(ce * entity){
    SM4_KEY sm4_key;

    sm4_set_decrypt_key(&sm4_key, entity->key);
    sm4_cbc_decrypt(&sm4_key, entity->iv, entity->cipher, entity->cipher_len/16 , entity->plain_2);
    return 0;
}


static int set_x509_name(uint8_t *name, size_t *namelen, size_t maxlen, se * entity){
    char * country = entity->country;
    char * locality = entity->locality;
    char * province = entity->province;
    char * organization = entity->organization;
    char * org_unit = entity->org_unit;
    char * common_name = entity->common_name;
    *namelen = 0;

    if (x509_name_add_country_name(name, namelen, maxlen, country) != 1
        || x509_name_add_locality_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)locality, strlen(locality)) != 1
        || x509_name_add_state_or_province_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)province, strlen(province)) != 1
        || x509_name_add_organization_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)organization, strlen(organization)) != 1
        || x509_name_add_organizational_unit_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)org_unit, strlen(org_unit)) != 1
        || x509_name_add_common_name(name, namelen, maxlen, ASN1_TAG_PrintableString, (uint8_t *)common_name, strlen(common_name)) != 1) {
        error_print();
        return -1;
    }
    return 1;
}

static int test_x509_cert_get(const uint8_t *cert, size_t certlen, SM2_KEY * public_key){
    const uint8_t *serial;
    size_t serial_len;
    const uint8_t *issuer;
    size_t issuer_len;
    const uint8_t *subject;
    size_t subject_len;

    if (x509_cert_get_issuer_and_serial_number(cert, certlen, &issuer, &issuer_len, &serial, &serial_len) != 1
        || x509_cert_get_subject(cert, certlen, &subject, &subject_len) != 1
        || x509_cert_get_subject_public_key(cert, certlen, public_key) != 1) {
        error_print();
        return -1;
    }
    format_bytes(stderr, 0, 4, "SerialNumber", serial, serial_len);
    x509_name_print(stderr, 0, 4, "Issuer", issuer, issuer_len);
    x509_name_print(stderr, 0, 4, "Subject", subject, subject_len);
    sm2_public_key_print(stderr, 0, 4, "SubjectPublicKey", public_key);

}

/*
 * 获取签名
 */
int getSign(char * filepath, uint8_t * sign, size_t * signlen, uint8_t * msg, size_t msg_len, char * pass){
    FILE * pem;
    SM2_KEY private_key;
    SM2_SIGN_CTX sign_ctx;

    if (!(pem = fopen(filepath, "r"))) {
        error_print();
        return -1;
    }
    if(sm2_private_key_info_decrypt_from_pem(&private_key, pass, pem) != 1 ){
        error_print();
        return -1;
    }
    //sm2_key_print(stderr, 0, 4, "SM2_KEY", &private_key);
    if (sm2_sign_init(&sign_ctx, &private_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
        || sm2_sign_update(&sign_ctx, msg, msg_len) != 1
        || sm2_sign_finish(&sign_ctx, sign, signlen) != 1) {
        error_print();
        return -1;
    }

    //sm2_key_print(stderr, 0, 4, "SM2_KEY", &sign_ctx.key);
    return 1;
}

/*
 * 验证签名
 */
int verifySign(char * filepath, uint8_t * sign, size_t signlen, uint8_t * msg, size_t msg_len){
    FILE * pem;
    uint8_t res[1024] = {0};
    size_t certlen = 0;
    SM2_KEY public_key;
    SM2_SIGN_CTX sign_ctx;
    int ret;

    if (!(pem = fopen(filepath, "r"))) {
        error_print();
        return -1;
    }

    if (x509_cert_from_pem(res, &certlen, 1024, pem) != 1){
        return -1;
    }
    //从证书读取公钥
    test_x509_cert_get(res, certlen, &public_key);

    if (sm2_verify_init(&sign_ctx, &public_key, SM2_DEFAULT_ID, SM2_DEFAULT_ID_LENGTH) != 1
        || sm2_verify_update(&sign_ctx, msg, msg_len) != 1
        || (ret = sm2_verify_finish(&sign_ctx, sign, signlen)) != 1) {
        sm2_key_print(stderr, 0, 4, "SM2_KEY", &sign_ctx.key);
        error_print();
        return -1;
    }
    format_print(stderr, 0, 4, "verification: %s\n", ret ? "success" : "failed");

    return 1;
}

/*
 * 测试
 */
int test_key(se * entity, SM2_KEY key, size_t len){
    FILE * prifp;
    FILE * pubfp;
    FILE * pem;
    SM2_KEY tmp_key;
    SM2_KEY tmp_key_pub;
    SM2_KEY tmp_key_pem;
    size_t tt = 0;

    if (!(prifp = fopen(entity->pripath, "r"))||
            !(pubfp = fopen(entity->pubpath, "r"))||
            !(pem = fopen(entity->filepath, "r"))) {
        error_print();
        return -1;
    }
    if (sm2_private_key_info_decrypt_from_pem(&tmp_key, entity->passwd, prifp) != 1
        || memcmp(&tmp_key, &key, sizeof(SM2_KEY)) != 0) {
        error_print();
        return -1;
    }

    fclose(prifp);

    if (sm2_public_key_info_from_pem(&tmp_key_pub, pubfp) != 1){
        return -1;
    }
    fclose(pubfp);

    uint8_t res[1024] = {0};
    if (x509_cert_from_pem(res, &tt, 1024, pem) != 1){
        return -1;
    }
    test_x509_cert_get(res, tt, &tmp_key_pem);
    x509_cert_to_pem(res, tt, stderr);

    return 1;
}

/*
 * 读取证书
 */
int getCertWith64(char * filepath, uint8_t * res, size_t * len){
    FILE * pem;
    if (!(pem = fopen(filepath, "r"))) {
        error_print();
        return -1;
    }
    if (x509_cert_from_pem(res, len, 1024, pem) != 1){
        return -1;
    }
    //x509_cert_to_pem(res, len, stderr);
    return 0;
}

/*
 * 保存私钥文件
 */
int savePrivateKey(SM2_KEY key, se* entity, size_t len){
    FILE * prifp;
    FILE * pubfp;

    if (!(prifp = fopen(entity->pripath, "w"))
        || !(pubfp = fopen(entity->pubpath, "w"))) {
        error_print();
        return -1;
    }

    if (sm2_private_key_info_encrypt_to_pem(&key, entity->passwd, prifp) != 1
        || sm2_public_key_info_to_pem(&key, pubfp) != 1) {
    }
    fclose(prifp);
    fclose(pubfp);
    test_key(entity, key, len);
    return 1;
}

int loadCAPrivateKey(se * entity, SM2_KEY * key){
    FILE * prifp;

    if (!(prifp = fopen(entity->capath, "r"))) {
        error_print();
        return -1;
    }

    if (sm2_private_key_info_decrypt_from_pem(key, entity->capasswd, prifp) != 1) {
        error_print();
        return -1;
    }
    return 0;
}

/*
 * 生成数字证书
 */
int test_x509_cert(se* entity){

    fprintf(stderr, "%s", entity->capath);
    uint8_t serial[20] = { 0x01, 0x00 };
    size_t serial_len;
    uint8_t issuer[256];
    size_t issuer_len = 0;
    time_t not_before, not_after;
    uint8_t subject[256];
    size_t subject_len = 0;
    SM2_KEY sm2_key;
    SM2_KEY ca_key;
    uint8_t cert[1024] = {0};
    uint8_t *p = cert;
    const uint8_t *cp = cert;
    size_t certlen = 0;

    set_x509_name(issuer, &issuer_len, sizeof(issuer), entity);
    time(&not_before);
    x509_validity_add_days(&not_after, not_before, 365);
    set_x509_name(subject, &subject_len, sizeof(subject), entity);
    sm2_key_generate(&sm2_key);
    loadCAPrivateKey(entity, &ca_key);

    //如果存在两个“&sm2_key”，那么就是自签名数字证书，利用自己的私钥对自己的信息做哈希
    if (x509_cert_sign(
            cert, &certlen, sizeof(cert),
            X509_version_v3,
            serial, sizeof(serial),
            OID_sm2sign_with_sm3,
            issuer, issuer_len,
            not_before, not_after,
            subject, subject_len,
            &sm2_key,
            NULL, 0,
            NULL, 0,
            NULL, 0,
            &ca_key, SM2_DEFAULT_ID, strlen(SM2_DEFAULT_ID)) != 1) {
        error_print();
        return -1;
    }
    FILE *fp;
    if (!(fp = fopen(entity->filepath, "w"))) {
        error_print();
        return -1;
    }
    x509_cert_to_pem(cert, certlen, fp);
    fclose(fp);

    savePrivateKey(sm2_key, entity, certlen);
    return 0;
}

int verifyCert(char * cacertfile, uint8_t * cert, size_t certlen){
    FILE *cacertfp = NULL;
    uint8_t cacert[1024] = {0};
    size_t cacertlen = 0;
    char signer_id[SM2_MAX_ID_LENGTH + 1] = {0};
    size_t signer_id_len = 0;
    strcpy(signer_id, SM2_DEFAULT_ID);
    signer_id_len = strlen(SM2_DEFAULT_ID);

    if (!(cacertfp = fopen(cacertfile, "rb"))) {
        fprintf(stderr, "open failure\n");
        return -1;
    }

    if (x509_cert_from_pem(cacert, &cacertlen, 1024, cacertfp) != 1){
        return -1;
    }

    if (x509_cert_verify_by_ca_cert(cert, certlen, cacert, cacertlen,
                                          signer_id, signer_id_len) != 1) {
        fprintf(stderr, "Verification failure\n");
        return -1;
    }

    fprintf(stderr, "Verification OK\n");

    return 0;
}

void getRandomSymKey(uint8_t * key){
    rand_bytes(key, SYNKEY_LEN);
}

int encryptRandomSymKey(uint8_t * randomkey, uint8_t * cert, size_t certlen, uint8_t * out, size_t * outlen){
    SM2_KEY pub_key;
    getRandomSymKey(randomkey);
    if (x509_cert_get_subject_public_key(cert, certlen, &pub_key) != 1) {
        error_print();
        return -1;
    }

    if(sm2_encrypt(&pub_key, randomkey, SYNKEY_LEN, out, outlen) != -1){
        error_print();
    }

    //sm2_encrypt(&pub_key, randomkey, SYNKEY_LEN, out, outlen);

    return 0;
}

int decryptRandomSymKey(char * pri_pem_path, uint8_t * in, size_t in_len, uint8_t * out, size_t * out_len){
    FILE * prifp;
    SM2_KEY pri_key;

    if (!(prifp = fopen(pri_pem_path, "r"))) {
        error_print();
        return -1;
    }

    if (sm2_private_key_info_decrypt_from_pem(&pri_key, "iamdsp", prifp) != 1) {
        error_print();
        return -1;
    }

    if(sm2_decrypt(&pri_key, in, in_len, out, out_len) != 1){
        error_print();
        return -1;
    }
    //sm2_decrypt(&pri_key, in, in_len, out, out_len);

    return 0;
}

int main() {
    int err = 0;
    //se * ss = (se *) malloc(sizeof (se));
    //ss->filepath = "tessssss.pem";
    //ss->country = "CN";
    //ss->locality = "DongLi";
    //ss->province = "TianJin";
    //ss->organization = "CAUC";
    //ss->org_unit = "AnQuan";
    //ss->common_name = "CA";
    //err += test_x509_cert(ss);
    uint8_t  msg[] = "Hello";
    size_t msglen = 5;
    uint8_t  sign[72] = {0};
    size_t signlen;


    char path[] = "/home/jiaxv/inoproject/Acars_Security/users/cmu/cmupri.pem";
    char pripath[] = "/home/jiaxv/inoproject/Acars_Security/users/cmu/cmucert.pem";

    char * passwd = "iamcmu";

    getSign(path, sign, &signlen, msg, msglen , passwd);
    verifySign(pripath, sign, signlen, msg, msglen);

    return err;
}
