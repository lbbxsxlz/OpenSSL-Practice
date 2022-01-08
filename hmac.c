#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

void output_hex(const unsigned char* input, unsigned int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", input[i]);
    }
    
    printf("\n");
}

int hmac(const char *algo, const char *txt, size_t txtLen, const char *keyStr, size_t keyStrLen) {
    if (algo == NULL || txt == NULL || keyStr == NULL) {
        printf("invalid parameters \n");
        return -1;
    }

    const EVP_MD *md = EVP_get_digestbyname(algo);
    if (md == NULL) {
        printf("unable to find the digest func: %s\n", algo);
        return -1;
    }

    unsigned char md_value[EVP_MAX_MD_SIZE] = "";
    unsigned int md_len = 0;

#if !defined(OPENSSL_VERSION_NUMBER) || OPENSSL_VERSION_NUMBER < 0x10100000L
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, keyStr, keyStrLen, md, NULL);
    HMAC_Update(&ctx, txt, txtLen);
    HMAC_Final(&ctx, md_value, &md_len);
    HMAC_CTX_cleanup(&ctx);
#else
    HMAC_CTX *ctx;
    ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, keyStr, keyStrLen, md, NULL);
    HMAC_Update(ctx, txt, txtLen);
    HMAC_Final(ctx, md_value, &md_len);
    HMAC_CTX_free(ctx);
#endif

    printf("%s: ", algo);
    output_hex(md_value, md_len);
    return 0;
}

int main(int argc, char** argv) 
{
    unsigned int len = 0;

    const char *txt = "Hello world, hello HMAC!";
    const char *keyStr = "123456789abcdef";
    
    //printf("0x%lx \n", OpenSSL_version_num());
    //printf("EVP_MAX_MD_SIZE = %d \n", EVP_MAX_MD_SIZE);
    
    unsigned char* result = calloc(EVP_MAX_MD_SIZE, sizeof(unsigned char));
    if (!result) {
        printf("calloc memory fail \n");
        return -1;
    }    
    
    HMAC(EVP_sha256(), keyStr, sizeof(keyStr), (unsigned char*)txt, sizeof(txt), result, &len);
    
    printf("EVP_sha256: ");
    output_hex(result, len);
    free(result);
    
    hmac("SHA1", txt, sizeof(txt), keyStr, sizeof(keyStr));
    hmac("SHA224", txt, sizeof(txt), keyStr, sizeof(keyStr));
    hmac("SHA256", txt, sizeof(txt), keyStr, sizeof(keyStr));
    hmac("SHA384", txt, sizeof(txt), keyStr, sizeof(keyStr));
    hmac("SHA512", txt, sizeof(txt), keyStr, sizeof(keyStr));

    return 0;
}
