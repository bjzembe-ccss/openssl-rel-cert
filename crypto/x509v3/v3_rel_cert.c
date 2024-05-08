/*
 * Copyright 2006-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "crypto/asn1.h"
#include "crypto/evp.h"
#include "crypto/ctype.h"
#include "ext_dat.h"
#include "include/crypto/x509.h"
#include "internal/cryptlib.h"

const char* tmp_file_name = "./TMP_REL_CERT.crt";

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
    // initialize extension ASN1 structure
    RELATED_CERTIFICATE* rel_cert = RELATED_CERTIFICATE_new();

    // extract variables
    unsigned int binary_time;
    char* issuer_and_serial;
    char* signature;
    char* location_info;
    char* access_method;
    char* access_location;
    int succeeded;

    for(int i = 0; i < sk_CONF_VALUE_num(values); ++i) {
        CONF_VALUE* value = sk_CONF_VALUE_value(values, i);
        if(strcmp(value->name, "certID") == 0) {
            issuer_and_serial = value->value;
        } else if (strcmp(value->name, "requestTime") == 0) {
            binary_time = atoi(value->value);
        } else if (strcmp(value->name, "signature") == 0) {
            signature = value->value;
        } else if (strcmp(value->name, "locationInfo") == 0) {
            location_info = value->value;
            succeeded = extract_access_params(location_info, &access_method, &access_location);

            if(!succeeded) {
                printf("ERROR: Failed to parse location info.\n");
                return NULL;
            }
        } else {
            // TODO: add checking for other variables?
        }
    }

    // pull related certificate into temporary file
    X509 rel_cert_x509;
    PKCS7 rel_cert_store;
    succeeded = get_related_cert(&rel_cert_x509, &rel_cert_store, access_location);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }

    // validate certificate
    succeeded = validate_certificate(&rel_cert_x509, &rel_cert_store, tmp_file_name, binary_time, issuer_and_serial, signature, ctx);
    if(!succeeded) {
        RELATED_CERTIFICATE_free(rel_cert);
        return NULL;
    }
    
    // extract fingerprint from related certificate
    char* fingerprint;
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

int extract_access_params(char* location_info, char** access_method, char** access_location) {
    // setup
    char loc_copy[strlen(location_info)];
    strcpy(loc_copy, location_info);

    // skip past "accessMethod = "
    if(strlen(loc_copy) < 16) {
        printf("ERROR: accessLocation string invalid\n");
        return 0;
    }
    memmove(loc_copy, loc_copy + 15, strlen(loc_copy));

    // split at ","
    char* method_str = strtok(loc_copy, ",");
    char* location_str = strtok(NULL, ",");

    // skip past " accessLocation = "
    memmove(location_str, location_str + 18, strlen(location_str));

    *access_method = method_str;
    *access_location = location_str;

    return 1;
}

int get_related_cert(X509* rel_cert, PKCS7* rel_cert_store, char* access_location) {
    /** TODO:
        Add authentication?
        Use built in SSL_* objects to make FTP/HTTP requests instead of c sockets?
    **/

    char* proto = "http"; // default: http
    char* address;
    char* filepath = '/';
    int port = 80;
    char loc_copy[strlen(access_location)];
    strcpy(loc_copy, access_location);

    char* token = strtok(loc_copy, ":");
    if(strlen(token) == strlen(access_location)) { // no ':' found
        // default to http

        // parse out filepath
        char *fp_token = strchr(token, ' ');
        if(fp_token) {
            filepath = fp_token;

            // recover address
            int addr_len = fp_token - token;
            strncpy(address, token, addr_len);
        } else {
            strcpy(address, token);
        }
    } else if(strcmp(token, "http") && strcmp(token, "ftp")) {
        // incorrect protocol or none included
        address = token;

        token = strtok(NULL, ":");
        if(token) {
            port = atoi(token);
        }

        // parse out filepath
        char *fp_token = strchr(token, '/');
        if(fp_token) {
            filepath = fp_token;
        }
    } else {
        proto = token;
        if(!strcmp(token, "ftp")) {
            port = 21;
        }

        token = strtok(NULL, ":");
        token = token + 2; // remove "//" in "proto://"
        address = token;
        token = strtok(NULL, ":");
        if(token) {
            port = atoi(token);
        }

        // parse out filepath
        char *fp_token = strchr(token, '/');
        if(fp_token) {
            filepath = fp_token;
        }
    }

    // establish a connection
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, address, &addr.sin_addr);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if(sock < 0) {
        printf("ERROR: Unable to create socket. %d\n", sock);
        return 0;
    }

    int succ = connect(sock, (struct sockaddr*) &addr, sizeof(addr));
    if(succ < 0) {
        printf("ERROR: Unable to bind. %d\n", succ);
        return 0;
    }

    if(!strcmp(proto, "http")) {
        // create request string
        char req_string[15 + strlen(filepath)];
        strcpy(req_string, "GET ");
        strcat(req_string, filepath);
        strcat(req_string, " HTTP/1.0\n\n");

        // send http request
        send(sock, req_string, strlen(req_string), 0);

        // create temp file to store rel cert
        FILE* tmp_file = fopen(tmp_file_name, "w");
        if(!tmp_file) {
            printf("ERROR: Could not create tmp file\n");
            return 0;
        }

        // pull related cert
        int buf_len = 4096;
        char* buf[buf_len];
        int bytes_rec = 0;
        do {
            // TODO: add delays to prevent race conditions? add retries/timeouts?
            bytes_rec = read(sock, buf, buf_len);
            succ = fputs(buf, tmp_file);
            if(succ <= 0) {
                printf("ERROR: fputs failed\n");
                return 0;
            }
        } while (bytes_rec != 0);
        
        // cleanup
        fclose(tmp_file);
    } else { // ftp
        // TODO: secure authentication? meh.
        // TODO: sleep more optimally?

        // error checking, woooo
        int success_codes[6] = {220, 331, 230, 227, 125, 226};
        char* error_msgs[6] = {
            "Failed to establish session.\n",
            "Invalid Username.\n",
            "Failed to authenticate with FTP server.\n",
            "Failed to establish session.\n",
            "Failed to initiate data transfer.\n",
            "Failed to complete data transfer.\n"
        };
        int i = 0;
        char status_code[4];
        char *token;

        // sign in anonymously
        char* anon_auth = "USER anonymous\r\nPASS anonymous\r\n";
        send(sock, anon_auth, strlen(anon_auth), 0);
        sleep(1);

        // connect to server
        char conn_status[256];
        int num_bytes = read(sock, conn_status, 255);
        conn_status[num_bytes] = '\0';
 
        // verify status codes
        token = strtok(conn_status, "\n");
        do {
            strncpy(status_code, token, 3);
            status_code[3] = '\0';
            if(atoi(status_code) != success_codes[i]) {
                printf("ERROR: %s\n", error_msgs[i]);
                return 0;
            }
            
            token = strtok(NULL, "\n");
            i++;
        } while(token != NULL);

        // intiate passive mode for data transfer
        char *pasv_mes = "PASV\r\n";
        char pasv_resp[256];
        send(sock, pasv_mes, strlen(pasv_mes), 0);
        sleep(1);
        num_bytes = read(sock, pasv_resp, 255);
        pasv_resp[num_bytes] = '\0';

        // verify status codes
        token = strtok(pasv_resp, "\n");
        char ip_mes[256];
        do {
            strncpy(status_code, token, 3);
            status_code[3] = '\0';
            if(atoi(status_code) != success_codes[i]) {
                printf("ERROR: %s\n", error_msgs[i]);
                return 0;
            }

            // extract pasv port message
            if(success_codes[i] == 227)
                strncpy(ip_mes, token, strlen(token));

            i++;
            token = strtok(NULL, "\n");
        } while(token != NULL);

        // get new port for data transfer
        char message[100];
        char ip1[10], ip2[10], ip3[10], ip4[10], p1[10], p2[10];
        int num_sects = sscanf(ip_mes, "%[^(](%[^,],%[^,],%[^,],%[^,],%[^,],%[^)])", message, ip1, ip2, ip3, ip4, p1, p2);

        if(num_sects != 7) {
            printf("ERROR: PASV mode message is unparcable.\n");
        }
        int data_port = atoi(p1)*256 + atoi(p2);

        // make new socket for file transfer
        struct sockaddr_in addr2;
        addr2.sin_family = AF_INET;
        addr2.sin_port = htons(data_port);
        inet_pton(AF_INET, address, &addr2.sin_addr);

        int sock2 = socket(AF_INET, SOCK_STREAM, 0);
        if(sock2 < 0) {
            printf("ERROR: Unable to create socket. %d\n", sock2);
            return 0;
        }

        int succ = connect(sock2, (struct sockaddr*) &addr2, sizeof(addr2));
        if(succ < 0) {
            printf("ERROR: Unable to bind. %d\n", succ);
            return 0;
        }        

        // create request string
        char retr_mes[15 + strlen(filepath)];
        strcpy(retr_mes, "RETR ");
        strcat(retr_mes, filepath);
        strcat(retr_mes, "\r\n");

        // initiate transfer
        char retr_resp[256];
        send(sock, retr_mes, strlen(retr_mes), 0);
        sleep(1);
        num_bytes = read(sock, retr_resp, 255);
        retr_resp[num_bytes] = '\0';

        // verify status
        token = strtok(retr_resp, "\n");
        do {
            strncpy(status_code, token, 3);
            status_code[3] = '\0';
            if(atoi(status_code) != success_codes[i]) {
                printf("ERROR: %s\n", error_msgs[i]);
                return 0;
            }

            token = strtok(NULL, "\n");
            i++;
        } while(token != NULL);

        // create temp file to store rel cert
        FILE* tmp_file = fopen(tmp_file_name, "w");
        if(!tmp_file) {
            printf("ERROR: Could not create tmp file\n");
            return 0;
        }

        // pull related cert
        int buf_len = 4096;
        char* buf[buf_len];
        int bytes_rec = 0;
        do {
            bytes_rec = read(sock2, buf, buf_len);
            succ = fputs(buf, tmp_file);
            if(succ <= 0) {
                printf("ERROR: fputs failed\n");
                return 0;
            }
        } while (bytes_rec != 0);

        // cleanup
        fclose(tmp_file);
        close(sock2);
    }
    close(sock);

    // create a new BIO to read the pulled cert
    BIO *rel_bio = BIO_new_file(tmp_file_name, "r");
    if(!rel_bio) {
        printf("ERROR: rel bio DNE\n");
        return 0;
    }

    // check if file is a chain
    PKCS7* p7;
    X509* retrieved_cert;

    char* ext = strchr(filepath, '.');
    if(!(strcmp(".p7b", ext)
      && strcmp(".p7c", ext)
      && strcmp(".p7m", ext)
      && strcmp(".p7r", ext)
      && strcmp(".p6s", ext)
    )){
        // extract pkcs7 cert chain from bio
        p7 = PEM_read_bio_PKCS7(rel_bio, NULL, NULL, NULL);
        /*p7 = d2i_PKCS7_bio(rel_bio, NULL);*/

        if(!p7) {
            printf("ERROR RETRIEVING PKCS7 STORE\n");
            return 0;
        }

        rel_cert_store = p7;
    } else {
        // extract related cert into X509 object
        X509* retrieved_cert = PEM_read_bio_X509(rel_bio, NULL, 0, NULL);
        if(!retrieved_cert) {
            printf("ERROR RETRIEVING RELATED CERTIFICATE\n");
            return 0;
        }
        rel_cert = retrieved_cert;
    }

    return 1;
} 

int validate_certificate(X509* rel_cert, PKCS7* rel_cert_store, char* tmp_file_name, int binary_time, char* issuer_and_serial, char* signature, X509V3_CTX *ctx) {
    STACK_OF(X509)* trusted_certs = sk_X509_new_null();

    int succeeded;
    int found_rel_cert = 0;
    char* issuer;
    unsigned char* serial;
    if(rel_cert_store) {
        /*
            For some reason, any pkcs7 files which I create get the NID type of "email" assigned
            to it, which causes the pkcs7_verify function and the get0_signers function to fail.
            I really have no idea why this happens, but this needs to be fixed before being able
            to use any of the pkcs7 functions to extract the related certificate chain
        */
        int res = PKCS7_verify(rel_cert_store, NULL, NULL, NULL, NULL, 0);
        STACK_OF(X509)* all_certs = PKCS7_get0_signers(rel_cert_store, NULL, 0);
        
        // parse out related certs vs. trusted certs
        X509* this_cert;
        while(this_cert = sk_X509_pop(all_certs)) {
            succeeded = validate_issuer_and_serial(rel_cert, tmp_file_name, issuer_and_serial, &issuer, &serial);

            if(succeeded) {
                // this_cert is the related cert
                rel_cert = this_cert;
                found_rel_cert = 1;
            } else {
                // this_cert is a trusted cert
                sk_X509_push(trusted_certs, this_cert);
            }
        }

        if(!rel_cert) {
            printf("ERROR: Could not extract related cert from PKCS7 file.\n");
            return 0;
        }

    } // else, related cert should be self signed

    // verify the binary time is sufficiently fresh
    succeeded = validate_binary_time(binary_time);
    if(!succeeded) {
        return 0;
    }

    // validate the related certificate
    succeeded = validate_related_cert(trusted_certs, rel_cert);
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

int validate_issuer_and_serial(X509* rel_cert, char* tmp_file_name, char* issuer_and_serial, char** issuer, unsigned char** serial) {
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

int extract_fingerprint(X509* rel_cert, char** fingerprint, int* finger_len) {
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

int validate_related_cert(STACK_OF(X509)* trusted_certs, X509* rel_cert) {
    // create store containing the (trusted) certs used to sign the related cert
    X509_STORE* store = X509_STORE_new();

    X509* this_cert;
    while(this_cert = sk_X509_pop(trusted_certs)) {
        X509_STORE_add_cert(store, this_cert);
    }
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

int verify_signature(char* signature, X509* rel_cert, unsigned int requestTime, const char* issuer, const unsigned char* serial_raw) {
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

    // convert hex to binary
    long siglen;
    unsigned char *bin_signature = OPENSSL_hexstr2buf(signature, &siglen);

    // initialize verification procedure
    const EVP_MD *evp_alg = EVP_get_digestbyobj(rel_cert->sig_alg.algorithm);
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
 
