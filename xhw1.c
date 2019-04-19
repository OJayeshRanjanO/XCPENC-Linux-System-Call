#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/md5.h>

#ifndef __NR_cpenc
#error cpenc system call not defined
#endif

struct user_args 
{ 
   char * infile;
   char * outfile; 
   void * keybuf;
   int keylen; 
   short flags;
} ;


/*Source taken from : https://stackoverflow.com/questions/7627723/how-to-create-a-md5-hash-of-a-string-in-c*/
void compute_md5(char * string, void ** digest, int keylen) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, string, keylen); 
    MD5_Final((unsigned char *)(*digest), &ctx);
}

void print_help(){
	printf("\nUSAGE -\n");
	printf("Help Menu\t\t: ./xcpenc -h \n");
	printf("Decrypt or Encrypt\t: ./xcpenc [-d|-e] [INPUT_FILE_PATH OUTPUT_FILE_PATH] [-p PASSWORD PASSWORD-LENGTH] \n");
	printf("Copy Files\t\t: ./xcpenc [-c]  [INPUT_FILE_PATH OUTPUT_FILE_PATH] \n");
}

int main(int argc, char *argv[])
{
	struct user_args * ag = calloc(sizeof(struct user_args),0);//NOTE: DO FREE	
	char c;
	char flags = 0;
	int i,rc = 0;
	void * password = NULL;
	ag->infile = NULL;
	ag->outfile = NULL;
	ag->keybuf = NULL;
	ag->keylen = 0;
	//char *p

	while ((c = getopt (argc, argv, "he:d:c:p:")) != -1){
		switch(c){
			printf("TEST\n");
			return 0;
			case 'p':
				password = calloc(strlen(optarg)+1,'\0');//NOTE: DO FREE
				memcpy(password,optarg,strlen(optarg)+1);
				for (i = 0; i < argc;i++){
					if (strcmp(argv[i],"-p")==0){
						ag->keylen = 16;//(int)strtol(argv[i+2], &p, 10);
						break;
					}
				}
				break;
			case 'e':
				if ( flags!=0 ){
					rc = -EINVAL;
					goto exit_function;
				}
				ag->infile = malloc(strlen(optarg)+1);//NOTE: DO FREE
				memset(ag->infile, strlen(optarg)+1 , '\0');
				strcpy(ag->infile,optarg);	
				for (i = 0; i < argc;i++){
					if (strcmp(argv[i],"-e")==0){
						ag->outfile = malloc(strlen(argv[i+2])+1);
						memset(ag->outfile, strlen(argv[i+2])+1, '\0');
						strcpy(ag->outfile,argv[i+2]);
						break;
					}
				}
				flags = 1;
				break;
			case 'd':
				if ( flags!=0 ){
					rc = -EINVAL;
					goto exit_function;
				}
				ag->infile = malloc(strlen(optarg)+1);//NOTE: DO FREE
				memset(ag->infile, strlen(optarg)+1 , '\0');
				strcpy(ag->infile,optarg);	
				for (i = 0; i < argc;i++){
					if (strcmp(argv[i],"-d")==0){
						ag->outfile = malloc(strlen(argv[i+2])+1);
						memset(ag->outfile, strlen(argv[i+2])+1, '\0');
						strcpy(ag->outfile,argv[i+2]);
						break;
					}
				}
				flags = 2;
				break;
			case 'c':
				if ( flags!=0 ){
					rc = -EINVAL;
					goto exit_function;
				}
				printf("%s\n",optarg);
				printf("%lu\n", strlen(optarg)+1) ;
				ag->infile = malloc(strlen(optarg)+1);//NOTE: DO FREE
				memset(ag->infile, strlen(optarg)+1 , '\0');
				strcpy(ag->infile,optarg);
				for (i = 0; i < argc;i++){
					if (strcmp(argv[i],"-c")==0){
						ag->outfile = malloc(strlen(argv[i+2])+1);
						memset(ag->outfile, strlen(argv[i+2])+1, '\0');
						strcpy(ag->outfile,argv[i+2]);
						break;
					}
				}
				flags = 4;

				break;
			case 'h':
				print_help();
				rc = 0;
				goto exit_function;
				break;

		}
	
	}
	
	if (ag->keylen < 6){
		rc = -EINVAL;
		goto exit_function;
	}
	if ( strlen(password) != ag->keylen ){
		rc = -EACCES;
		goto exit_function;
 	} 
	/* Taken from: https://stackoverflow.com/questions/230062/whats-the-best-way-to-check-if-a-file-exists-in-c*/			 if( access( ag->infile , F_OK ) == -1 ) {
   		printf("inFile not exists");
		rc = -ENOENT;
		goto exit_function;
	}
	if (ag->infile == NULL || ag->outfile == NULL){
		rc = -ENOENT;
		goto exit_function;
	}
	if (ag->keylen == 0 && flags == 4){
		rc = -EINVAL;
		goto exit_function;
	}
	if (flags == 1 && flags == 2){
		ag->keybuf = calloc(ag->keylen,0);
		compute_md5((char *)password,&ag->keybuf,ag->keylen);
	}


	ag->flags = flags;

 	void *dummy = (void *) ag;
	printf("%p",dummy);	
  	rc = syscall(__NR_cpenc, dummy);
	

	exit_function:
	if (rc){
		print_help();
	}
	errno = rc;
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);


	//if (ag->keybuf)
	//	free(ag->keybuf);
	//if (ag->outfile)
	//	free(ag->outfile);
	//if (ag->infile){
//		free(ag->infile);
//	}
	//if (password)
	//	free(password);
	//if (ag){
	//	free(ag);
	//}
	exit(rc);
	return 0;
}


