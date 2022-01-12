#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

int main(int argc, char **argv) 
{
    EC_KEY *key = EC_KEY_new();
    if (!key) {
        printf("Unable to create EC key structure.\n");
        return -1;
    }
    
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp256k1);
    if (!group) {
        printf("get EC_GROUP by curve fail \n");
        goto quit;
    }
    
    int ret = EC_KEY_set_group(key, group);
    if (ret != 1) {
        printf("set EC_GROUP fail \n");
        goto quit;
    }

    ret = EC_KEY_generate_key(key);
    if (ret != 1) {
        printf("generate EC key fail \n");
        goto quit;
    }
    
    EC_KEY_print_fp(stdout, key, 0);

 
    FILE* pri = fopen(argv[1], "wb");
    FILE* pub = fopen(argv[2], "wb");
 
    PEM_write_EC_PUBKEY(pub, key);
    PEM_write_ECPrivateKey(pri, key, 0, 0, 0, 0, 0);
 
    fclose(pri);
    fclose(pub);
    pri = NULL;
    pub = NULL;
    
quit:
    if (key) {
        EC_KEY_free(key);
    }
    
    if (group) { 
        EC_GROUP_clear_free(group);
    }

    return 0;
}
