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

    char* tmp_file_name = "./TMP_REL_CERT.crt";
    FILE* tmp_file = fopen(tmp_file_name, "w");

    if(!tmp_file) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }

    // pull related certificate into temporary file
    int succeeded = get_related_cert(tmp_file, values);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }
    fclose(tmp_file);

    // validate certificate
    succeeded = validate_certificate(tmp_file_name, values, ctx);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }

    // extract fingerprint from related certificate
    unsigned char* fingerprint;
    succeeded = extract_fingerprint(tmp_file_name, &fingerprint);
    
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }

    // add fingerprint to attribute
    ASN1_OCTET_STRING* value_asn1 = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(value_asn1, fingerprint, strlen((const char *) fingerprint));

    rel_cert->RelatedCertificate = *value_asn1;

    // remove tmp files
    remove(tmp_file_name);
    return rel_cert;
}

int get_related_cert(FILE* tmp_file, STACK_OF(CONF_VALUE)* values) {
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

    return 1;
} 

int validate_certificate(char* tmp_file_name, STACK_OF(CONF_VALUE)* values, X509V3_CTX *ctx) {
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
    //TODO: not hardcode the trusted cert
    char* trusted_file = "/home/ubuntu/ca/certs/rsa4096_root.crt";
    BIO *trusted_bio = BIO_new_file(trusted_file, "r");
    X509 *trusted_cert = PEM_read_bio_X509(trusted_bio, NULL, 0, NULL);    

    // load related cert file into BIO
    BIO *rel_bio = BIO_new_file(tmp_file_name, "r");

    // extract related cert into X509 object
    X509 *rel_cert = PEM_read_bio_X509(rel_bio, NULL, 0, NULL);

    // verify issuers and serial numbers match
    char* issuer;
    char* serial;
    int succeeded = validate_issuer_and_serial(tmp_file_name, issuer_and_serial, &issuer, &serial);

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

int validate_issuer_and_serial(char* tmp_file_name, char* issuer_and_serial, char** issuer, char** serial) {
    char oqs_loc[512] = "/home/ubuntu/public_related_certs/openssl-rel-cert/apps/openssl";
    char issuer_file_name[512] = "./TMP_ISSUER.txt";
    char issuer_cmd[512] = "";
    strcat(issuer_cmd, oqs_loc);
    strcat(issuer_cmd, " x509 -noout -issuer -in ");
    strcat(issuer_cmd, tmp_file_name);
    strcat(issuer_cmd, " -out ");
    strcat(issuer_cmd, issuer_file_name);

    system(issuer_cmd);

    char serial_file_name[512] = "./TMP_SERIAL.txt";
    char serial_cmd[512] = "";
    strcat(serial_cmd, oqs_loc);
    strcat(serial_cmd, " x509 -noout -serial -in ");
    strcat(serial_cmd, tmp_file_name);
    strcat(serial_cmd, " -out ");
    strcat(serial_cmd, serial_file_name);

    system(serial_cmd);

    // parse issuer and serial
    FILE* issuer_file = fopen(issuer_file_name, "r");
    FILE* serial_file = fopen(serial_file_name, "r");
    char issuer_buff[2048];
    char serial_buff[2048];

    fgets(issuer_buff, 2048, issuer_file);
    fgets(serial_buff, 2048, serial_file);

    // remove trailing newlines
    issuer_buff[strlen(issuer_buff)-1] = '\0';
    serial_buff[strlen(serial_buff)-1] = '\0';
    
    char rel_issuer_and_serial[4096] = "";
    strcat(rel_issuer_and_serial, issuer_buff);
    strcat(rel_issuer_and_serial, ", ");
    strcat(rel_issuer_and_serial, serial_buff);
    
    // cleanup
    fclose(issuer_file);
    fclose(serial_file);
    remove(issuer_file_name);
    remove(serial_file_name);

    // extract issuer & serial values
    
    *issuer = issuer_buff + 7;
    *serial = serial_buff + 7;

    return !strcmp(issuer_and_serial, rel_issuer_and_serial);
}

int validate_binary_time(unsigned int binary_time) {
    unsigned int diff = time(NULL) - binary_time;

    // temporarily: verify cert was issued in the last year
    return diff < (60*60*24*365);
}

int extract_fingerprint(char* tmp_file_name, char** fingerprint) {
    // TODO: use the correct hashing algorithm
    // TODO: do this programmatically instead of through a shell command
    char oqs_loc[512] = "/home/ubuntu/public_related_certs/openssl-rel-cert/apps/openssl";
    char fingerprint_file_name[512] = "./TMP_FINGERPRINT.txt";
    char fingerprint_cmd[512] = "";
    strcat(fingerprint_cmd, oqs_loc);
    strcat(fingerprint_cmd, " x509 -noout -fingerprint -sha256 -in ");
    strcat(fingerprint_cmd, tmp_file_name);
    strcat(fingerprint_cmd, " -out ");
    strcat(fingerprint_cmd, fingerprint_file_name);

    system(fingerprint_cmd);

    // parse fingerprint
    FILE* fingerprint_file = fopen(fingerprint_file_name, "r");
    char fingerprint_buff[2048];
    fgets(fingerprint_buff, 2048, fingerprint_file);

    char* extracted = strtok(fingerprint_buff, "=");
    
    if(!extracted) {
        // fingerprint calculation failed; no '=' exists
        return 0;
    }

    // copy value after '=' into fingerprint
    extracted = strtok(NULL, "=");

    // remove trailing newspace
    extracted[strlen(extracted)-1] = '\0';

    // overwrite referenced fingerprint value
    *fingerprint = extracted;

    // cleanup
    fclose(fingerprint_file);
    remove(fingerprint_file_name);

    return 1;
}

int validate_related_cert(X509* trusted_cert, X509* rel_cert) {
    /*TODO:
        - create the X509* rel cert variable earlier in the process
        - pass the x509* variable to this function
        - implement other verification functions using the X509* variable
            instead of through system commands
    */

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

int verify_signature(char* signature, X509* rel_cert, unsigned int requestTime, const char* issuer, const char* serial) {
    /*
        The signature field contains a digital signature over the
        concatenation of DER encoded requestTime and IssuerAndSerialNumber
    */
    // reconstruct the signed data
    // TODO: signed_data ?= concat(DER(time), DER(iss and ser))

    char data[256];
    sprintf(data, "%u", requestTime);

    int data_len = strlen(data) + strlen(issuer) + strlen(serial);

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
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
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
 
