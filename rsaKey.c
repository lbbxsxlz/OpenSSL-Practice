#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

int main(int argc, char **argv) {
    RSA *rsa = RSA_new();
    if (!rsa) {
        printf("Unable to create RSA structure.\n");
        return -1;
    }
    
    BIGNUM *bne = BN_new();
    if (!bne) {
        printf("get BigNum structure fail \n");
        goto quit;
    }
    
    BN_set_word(bne, RSA_F4);

    int ret = RSA_generate_key_ex(rsa, 3072, bne, NULL);
    if (!ret) {
        printf("generate rsa key fail \n");
        goto quit;
    }
    RSA_print_fp(stdout, rsa, 0);
 
    FILE* pri = fopen("private.key", "wb");
    FILE* pub = fopen("public.key", "wb");
 
    PEM_write_RSAPublicKey(pub, rsa);
    PEM_write_RSAPrivateKey(pri, rsa, 0, 0, 0, 0, 0);
 
    fclose(pri);
    fclose(pub);
    pri = NULL;
    pub = NULL;
    
quit:
    if (rsa) {
        RSA_free(rsa);
    }
    
    if (bne) { 
        BN_free(bne);
    }

    return 0;
}
