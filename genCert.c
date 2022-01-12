#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

/* Generates a 3072-bit RSA key. */
EVP_PKEY* generate_rsa_key()
{
    int ret = 0;
    
    RSA *rsa = RSA_new();
    if (!rsa) {
        printf("Unable to create RSA structure.\n");
        return NULL;
    }
    
    /* Generate the RSA key. */
    //rsa = RSA_generate_key(3072, RSA_F4, NULL, NULL);
    BIGNUM *bne = BN_new();
    if (!bne) {
        printf("get BigNum structure fail \n");
        goto quit;
    }
    
    ret = BN_set_word(bne, RSA_F4);
    if (!ret) {
        printf("get BigNum fail \n");
        goto quit;
    }
    
    ret = RSA_generate_key_ex(rsa, 3072, bne, NULL);
    if (!ret) {
        printf("generate rsa key fail \n");
        goto quit;
    }
	
    /* Assign rsa key to pkey. */
    /* Allocate memory for the EVP_PKEY structure. */
    EVP_PKEY *pkey = EVP_PKEY_new();
    if(!pkey) {
        printf("Unable to create EVP_PKEY structure.\n");
        goto quit;
    }
	
    if(!EVP_PKEY_assign_RSA(pkey, rsa)) {
        printf("Unable to generate 3072-bit RSA key.\n");
        goto quit;
    }
    
    BN_free(bne);
    /* The key has been generated, return it. */
    return pkey;
    
quit:
    if (rsa) {
        RSA_free(rsa);
    }
    
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    
    if (bne) {
        BN_free(bne);
    }
}

/* Generates a self-signed x509 certificate. */
X509* generate_x509(EVP_PKEY *pkey)
{
    /* Allocate memory for the X509 structure. */
    X509 * x509 = X509_new();
    if(!x509) {
        printf("Unable to create X509 structure.\n");
        return NULL;
    }
    
    X509_set_version(x509, 2);
    /* Set the serial number. */
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    /* This certificate is valid from now until exactly one year from now. */
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);
    
    /* Set the public key for our certificate. */
    X509_set_pubkey(x509, pkey);
    
    /* We want to copy the subject name to the issuer name. */
    X509_NAME *name = X509_get_subject_name(x509);
    
    /* Set the country code and common name. */
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char *)"CN",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *)"SH",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L",  MBSTRING_ASC, (unsigned char *)"SH",        -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char *)"MyCompany,Inc", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *)"QA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"OpenSSL Group", -1, -1, 0);
    
    /* Now set the issuer name. */
    X509_set_issuer_name(x509, name);
    
    /* Actually sign the certificate with our key. */
    if(!X509_sign(x509, pkey, EVP_sha256())) {
        printf("Error signing certificate.\n");
        X509_free(x509);
        return NULL;
    }
    
    return x509;
}

bool write_to_disk(EVP_PKEY *pkey, X509 *x509)
{
    /* Open the PEM file for writing the key to disk. */
    FILE *pkey_file = fopen("rsakey.pem", "wb");
    if(!pkey_file) {
        printf("Unable to open \"rsakey.pem\" for writing.\n");
        return false;
    }
    
    /* Write the key to disk. */
    bool ret = PEM_write_PrivateKey(pkey_file, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(pkey_file);
    
    if(!ret) {
        printf("Unable to write private key to disk.\n");
        return false;
    }
    
    /* Open the PEM file for writing the certificate to disk. */
    FILE *x509_file = fopen("certificate.pem", "wb");
    if(!x509_file) {
        printf("Unable to open \"certificate.pem\" for writing.\n");
        return false;
    }
    
    /* Write the certificate to disk. */
    ret = PEM_write_X509(x509_file, x509);
    fclose(x509_file);
    
    if(!ret) {
        printf("Unable to write certificate to disk.\n");
        return false;
    }
    
    return true;
}

int main(int argc, char **argv)
{
    /* Generate the key. */
    printf("Generating RSA key...");
    
    EVP_PKEY *pkey = generate_rsa_key();
    if(!pkey) {
        return 1;
    }
    
    /* Generate the certificate. */
    printf("Generating x509 certificate...\n");
    
    X509 *x509 = generate_x509(pkey);
    if(!x509) {
        EVP_PKEY_free(pkey);
        return 1;
    }
    
    /* Write the private key and certificate out to disk. */
    printf("Writing key and certificate to disk...\n");
    
    bool ret = write_to_disk(pkey, x509);
    EVP_PKEY_free(pkey);
    X509_free(x509);
    
    if(ret) {
        printf("Success!\n");
        return 0;
    }
    else {
        return 1;
    }    
}
