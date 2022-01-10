#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/sha.h>

void output_hex(const unsigned char* input, unsigned int len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x", input[i]);
    }
    
    printf("\n");
}

int hash(const char *algo, const char *input, unsigned int len)
{
    if (algo == NULL || input == NULL) {
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
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, md, NULL);
    EVP_DigestUpdate(&ctx, input, len);
    EVP_DigestFinal_ex(&ctx, (unsigned char *)md_value, &md_len);
    EVP_MD_CTX_cleanup(&ctx);
#else
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, NULL);
    EVP_DigestUpdate(ctx, input, len);
    EVP_DigestFinal_ex(ctx, (unsigned char *)md_value, &md_len);
    EVP_MD_CTX_free(ctx);
#endif
    
    printf("%s: ", algo);
    output_hex(md_value, md_len);
}

int main(int argc, char **argv) 
{
    unsigned int len = 0;
    const char *txt = "Hello world, hello hash!";
   
    //printf("0x%lx \n", OpenSSL_version_num());
    //printf("SHA512_DIGEST_LENGTH = %d \n", SHA512_DIGEST_LENGTH);
    unsigned char digest[SHA512_DIGEST_LENGTH];
#if 0     
    SHA512_CTX sha_ctx = {0};
    SHA512_Init(&sha_ctx);
    SHA512_Update(&sha_ctx, txt, sizeof(txt));
    SHA512_Final(digest, &sha_ctx);
#else
    SHA512(txt, sizeof(txt), digest);
#endif    
    printf("SHA512: ");
    output_hex(digest, SHA512_DIGEST_LENGTH);
    
    hash("SHA1", txt, sizeof(txt));
    hash("SHA224", txt, sizeof(txt));
    hash("SHA256", txt, sizeof(txt));
    hash("SHA384", txt, sizeof(txt));
    hash("SHA512", txt, sizeof(txt));

    return 0;
}
