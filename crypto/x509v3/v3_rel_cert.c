/*
 * Copyright 2006-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/objects.h>
#include <openssl/pem.h>

/*#include "openssl/apps.h"*/
#include "crypto/ctype.h"
/*#include "crypto/x509.h"*/
#include "ext_dat.h"
#include "internal/cryptlib.h"

#include "include/crypto/x509.h"
#include "crypto/asn1.h"
#include "crypto/evp.h"

/*#include "crypto/x509/x_pubkey.c"*/

const char* tmp_file_name = "./TMP_REL_CERT.crt";

struct X509_pubkey_st {
    X509_ALGOR *algor;
    ASN1_BIT_STRING *public_key;
    EVP_PKEY *pkey;
};
typedef struct X509_pubkey_st X509_PUBKEY;

ASN1_SEQUENCE(RELATED_CERTIFICATE) = {
    ASN1_SIMPLE(RELATED_CERTIFICATE, RelatedCertificate, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(RELATED_CERTIFICATE)

IMPLEMENT_ASN1_FUNCTIONS(RELATED_CERTIFICATE)

static int i2r_rel_cert(X509V3_EXT_METHOD *method, RELATED_CERTIFICATE *rel_cert, BIO *out, int indent) {
    if(rel_cert) {
        BIO_printf(out, "%*s%s", indent, "", rel_cert->RelatedCertificate.data);
        return 1;
    }

    return 0;
}

static void* v2i_rel_cert(const X509V3_EXT_METHOD *method, X509V3_CTX *ctx, STACK_OF(CONF_VALUE) *values) {
    RELATED_CERTIFICATE* rel_cert = RELATED_CERTIFICATE_new();

    // pull related certificate into temporary file
    X509 rel_cert_x509;
    int succeeded = get_related_cert(&rel_cert_x509, values);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }

    // validate certificate
    succeeded = validate_certificate(&rel_cert_x509, tmp_file_name, values, ctx);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }
    
    // extract fingerprint from related certificate
    unsigned char* fingerprint;
    unsigned int finger_len;
    succeeded = extract_fingerprint(&rel_cert_x509, &fingerprint, &finger_len);

    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }
    
    // add fingerprint to attribute
    ASN1_OCTET_STRING* value_asn1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(value_asn1, fingerprint, strlen((const char *) fingerprint));
    rel_cert->RelatedCertificate = *value_asn1;

    // cleanup
    remove(tmp_file_name);
    return rel_cert;
}

int get_related_cert(X509* rel_cert, STACK_OF(CONF_VALUE)* values) {
    /** TODO:
      * instead of accessing a local filepath, perform the following:
      *   - extract accessLocation from values
      *   - use curl (or an OQS internal package) to access the related cert
      *   - store file directly into 'tmp_file'
    **/

    // get related certificate
    /*CURL *curl = curl_easy_init();*/
    /*CURLcode res;*/
    /*if(curl) {*/
    /*curl_easy_setopt(curl, CURLOPT_URL, "http://0.0.0.0:8000/dil5_rsa4096_hybrid.crt");*/
    /*res = curl_easy_perform(curl);*/

    /*if(res != CURLE_OK)*/

    /*curl_easy_cleanup(curl);*/
    /*}*/

    FILE* tmp_file = fopen(tmp_file_name, "w");

    if(!tmp_file) {
        return 0;
    }

    FILE* in_file = fopen("/home/ubuntu/ra/related-certs-ra/certs/signed_rsa4096.crt", "r");
    if(!in_file) {
        return 0;
    }

    int buff_size = 16192; // TODO: optimize
    char rel_cert_buff[buff_size];

    // extract certificate into temporary file
    while(fgets(rel_cert_buff, buff_size, in_file)) {
        fputs(rel_cert_buff, tmp_file);
    }

    // cleanup
    fclose(in_file);
    fclose(tmp_file);

    // load related cert file into BIO
    BIO *rel_bio = BIO_new_file(tmp_file_name, "r");

    // extract related cert into X509 object
    X509* retrieved_cert = PEM_read_bio_X509(rel_bio, NULL, 0, NULL);

    if(!retrieved_cert) {
        printf("ERROR RETRIEVING RELATED CERTIFICATE\n");
        return 0;
    }

    *rel_cert = *retrieved_cert;

    return 1;
} 

int validate_certificate(X509* rel_cert, char* tmp_file_name, STACK_OF(CONF_VALUE)* values, X509V3_CTX *ctx) {
    // extract variables
    unsigned int binary_time;
    char* issuer_and_serial;
    char* signature;

    for(int i = 0; i < sk_CONF_VALUE_num(values); ++i) {
        CONF_VALUE* value = sk_CONF_VALUE_value(values, i);

        if(strcmp(value->name, "certID") == 0) {
            issuer_and_serial = value->value;
        } else if (strcmp(value->name, "requestTime") == 0) {
            char* binary_time_str = value->value;
            binary_time = atoi(value->value);
        } else if (strcmp(value->name, "signature") == 0) {
            signature = value->value;
        } else {
            // TODO: add checking for other variables
        }
    }

    // get trusted CA root cert
    // TODO: not hardcode the trusted cert
    char* trusted_file = "/home/ubuntu/ca/certs/rsa4096_root.crt";
    BIO *trusted_bio = BIO_new_file(trusted_file, "r");
    X509 *trusted_cert = PEM_read_bio_X509(trusted_bio, NULL, 0, NULL);    

    // verify issuers and serial numbers match
    char* issuer;
    char* serial;
    int succeeded = validate_issuer_and_serial(rel_cert, tmp_file_name, issuer_and_serial, &issuer, &serial);

    if(!succeeded) {
        return 0;
    }

    // verify the binary time is sufficiently fresh
    succeeded = validate_binary_time(binary_time);
    if(!succeeded) {
        return 0;
    }

    // validate the related certificate
    succeeded = validate_related_cert(trusted_cert, rel_cert);
    if(!succeeded) {
        return 0;
    }

    // verify the referenced signature value using the extracted public key
    succeeded = verify_signature(signature, rel_cert, binary_time, issuer, serial);
    if(!succeeded) {
        return 0;
    }

    return 1;
}

int validate_issuer_and_serial(X509* rel_cert, char* tmp_file_name, char* issuer_and_serial, char** issuer, char** serial) {
    long iss_and_serial_len = strlen(issuer_and_serial);
    
    // extract issuer data from rel_cert into a BIO
    BIO *issuer_bio = BIO_new(BIO_s_mem());
    X509_NAME_print(issuer_bio, rel_cert->cert_info.issuer, 0);

    // extract issuer string from bio
    BUF_MEM *bio_memory;
    BIO_get_mem_ptr(issuer_bio, &bio_memory);
    BIO_set_close(issuer_bio, BIO_NOCLOSE);
    char* rel_issuer = (char *) malloc(bio_memory->length+1);
    memcpy(rel_issuer, bio_memory->data, bio_memory->length);
    rel_issuer[bio_memory->length] = '\0';
    BIO_free(issuer_bio);

    // extract issuer from extension value
    char iss_copy[iss_and_serial_len];
    strcpy(iss_copy, issuer_and_serial);

    char* ext_issuer = strstr(iss_copy, "=");
    if(ext_issuer[1] == ' ') {
        // issuer string has a space after =
        ext_issuer += 2;
    } else {
        ext_issuer += 1;
    }

    ext_issuer[strlen(rel_issuer)] = '\0';

    ASN1_INTEGER rel_serial = rel_cert->cert_info.serialNumber;
    char* rel_serial_hex = OPENSSL_buf2hexstr(rel_serial.data, rel_serial.length);
    int rel_serial_hex_len = strlen(rel_serial_hex);

    // grab the last 'rel_serial_hex_len' bytes from iss_and_ser string
    char* ext_serial_str = issuer_and_serial + iss_and_serial_len - rel_serial_hex_len;
    ASN1_INTEGER *ext_serial = ASN1_INTEGER_new();
    long raw_serial_len;
    unsigned char* serial_raw = OPENSSL_hexstr2buf(ext_serial_str, &raw_serial_len);

    // create ASN1_INTEGER object from serial num
    c2i_ASN1_INTEGER(&ext_serial, &serial_raw, raw_serial_len);

    // compare
    int iss_cmp = strcmp(ext_issuer, rel_issuer);
    int ser_cmp = ASN1_INTEGER_cmp(&rel_serial, ext_serial);

    int cmp = iss_cmp || ser_cmp;
    int ok;
    if(cmp) {
        // failed
        printf("ERROR IN ISSUER AND SERIAL COMPARISON");
        ok = 0;
    } else {
        *issuer = rel_issuer;
        *serial = rel_serial.data;
        ok = 1;
    }

    return ok;
}

int validate_binary_time(unsigned int binary_time) {
    unsigned int diff = time(NULL) - binary_time;

    // temporarily: verify cert was issued in the last year
    return diff < (60*60*24*365);
}

int extract_fingerprint(X509* rel_cert, unsigned char** fingerprint, int* finger_len) {
    // get the hashing algorithm used on the related cert
    EVP_MD *alg = EVP_get_digestbyobj(rel_cert->sig_alg.algorithm);

    // get digest of the entire related cert
    unsigned char digest_value[256];
    unsigned int digest_len = 0;
    int ok = X509_digest(rel_cert, alg, &digest_value, &digest_len);
    if(!ok) {
        printf("ERROR IN FINGERPRINT EXTRACTION\n");
        return 0;
    }

    // convert to hex
    *fingerprint = OPENSSL_buf2hexstr(digest_value, digest_len);
    *finger_len = strlen(*fingerprint);

    return 1;
}

int validate_related_cert(X509* trusted_cert, X509* rel_cert) {
    // create store containing the (trusted) cert used to sign the related cert
    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store, trusted_cert);
    X509_STORE_set_default_paths(store);

    // add related cert to a chain of certs to be verified
    STACK_OF(X509) *chain = sk_X509_new_null();
    sk_X509_push(chain, rel_cert);

    // create store ctx object
    X509_STORE_CTX *ctx_store = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx_store, store, rel_cert, chain);

    // verify cert
    int succ = X509_verify_cert(ctx_store);

    // cleanup
    X509_STORE_CTX_free(ctx_store);
    
    if(succ <= 0) {
        // failure
        return 0;
    }
    
    return 1;
}

int verify_signature(char* signature, X509* rel_cert, unsigned int requestTime, const char* issuer, const char* serial_raw) {
    /*
        The signature field contains a digital signature over the
        concatenation of DER encoded requestTime and IssuerAndSerialNumber
    */
    // TODO: signed_data ?= concat(DER(time), DER(iss and ser))

    // setup
    char* serial = OPENSSL_buf2hexstr(serial_raw, strlen(serial_raw));
    char data[256];
    sprintf(data, "%u", requestTime);
    int data_len = strlen(data) + strlen(issuer) + strlen(serial);

    // reconstruct the signed data
    strcat(data, issuer);
    strcat(data, serial);
    data[data_len] = '\0';

    // extract public key from related certificate
    EVP_PKEY *pkey = X509_get0_pubkey(rel_cert);
    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, NULL);

    // convert hex to binary
    long siglen;
    unsigned char *bin_signature = OPENSSL_hexstr2buf(signature, &siglen);

    // initialize verification procedure
    EVP_MD *evp_alg = EVP_get_digestbyobj(rel_cert->sig_alg.algorithm);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(mdctx, NULL, evp_alg, NULL, pkey);
    ok &= EVP_DigestVerifyUpdate(mdctx, data, data_len);
    if(ok != 1) {
        printf("ERROR IN SIGNATURE INITIALIZATION: %d\n", ok);
        return 0;
    }

    // verify signature
    ok = EVP_DigestVerifyFinal(mdctx, bin_signature, siglen);
    if (ok != 1) {
        printf("ERROR IN SIGNATURE VERIFICATION: %d\n", ok);
        return 0;
    }

    return 1;
}

const X509V3_EXT_METHOD v3_rel_cert = {
    NID_relatedCertRequest,         /* nid */
    0,                              /* flags */
    ASN1_ITEM_ref(ASN1_INTEGER),    /* template */
    0, 0, 0, 0,                     /* old functions, ignored */
    0,                              /* i2s */
    0,                              /* s2i */
    0,                              /* i2v */
    v2i_rel_cert,                   /* v2i */
    i2r_rel_cert,                   /* i2r */
    0,                              /* r2i */
    NULL                            /* extension-specific data */
};
 
