struct user_args
{
   char * infile;
   char * outfile;
   void * keybuf;
   int keylen;
   short flags;
};

struct tcrypt_result {
    struct completion completion;
    int err;
};

/* tie all data structures together */
struct skcipher_def {
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct tcrypt_result result;
};


asmlinkage extern long (*sysptr)(void *arg);
static int cipher(void ** buffer, int buffer_size, void * key,int enc_dec_flag);
static unsigned int encdec(struct skcipher_def *sk,int enc);
int md5(char * string, void ** digest, int keylen);
