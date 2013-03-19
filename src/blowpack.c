/**
 * blowpack.c -- Run a file through a non-chaining Blowfish cipher and insert
 *               a bogus LZSS header for use with certain versions of AIMS.
 * written on 2013-03-14 by K
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <unistd.h>
#include <libgen.h>
#include <errno.h>

#include "blowfish.h"

FILE *cryptfile, *keyfile;

char *in_buff, *out_buff;

BLOWFISH_CTX cipher;
unsigned char blowfish_key[56];

typedef struct {
    uint32_t magic; // "LZSS"
    uint32_t size; // simply the filesize, for varying definitions of "simply"
} boguslzss;


int main(int argc, char *argv[]) {
    if(argc <= 1) {
        printf("blowpack: Encrypt files using non-chaining Blowfish algorithm. \n");
        printf("Usage: blowpack cryptfile \n"); // TODO: add decode (decrypt/strip header) mode
        return EXIT_FAILURE;
    }

	/* prepare key file and cipher */
	size_t keysize;
	keyfile = fopen("thmj3g.key", "rb"); // TODO: refactor out into commandline arg
	if(keyfile == NULL) {
		perror("  - KEYFILE ERROR: ");
	}
	fseek(keyfile, 0, SEEK_END);
	keysize = ftell(keyfile);
	rewind(keyfile);
	fread(blowfish_key, sizeof(unsigned char), keysize, keyfile);
	fclose(keyfile);
	
	Blowfish_Init(&cipher, blowfish_key, keysize);
    
	
	/* read file in */
    if((cryptfile = fopen(argv[1], "rb")) == NULL) {
        printf("ERROR: %s could not be read or does not exist.\n", argv[1]);
        return EXIT_FAILURE;
    }
	
	fseek(cryptfile, 0, SEEK_END);
	size_t filesize = ftell(cryptfile);
	
    in_buff = (char*) malloc((sizeof(char) * filesize));
	
	rewind(cryptfile);
    size_t result = fread(in_buff, 1, filesize, cryptfile);


	if(result != filesize) {
        printf("  - WARNING: Expected %d bytes, only read %d bytes.\n", filesize, result);
    }
	
	fclose(cryptfile);
	
	/* generate bogus LZSS header */
	boguslzss header;
	header.magic = 0x53535A4C; // "LZSS"
	header.size = result; // non-padded value
	
	result = (result + 7) & ~7; // padding
	
	out_buff = (char*) malloc((sizeof(char) * result));
	
	/* ciphering */
	int half_block = sizeof(unsigned long);
	int j;
	unsigned long L, R;
	for(j=0; j<result; j+=(2*half_block)) {
		memcpy(&L, &in_buff[j], half_block);
		memcpy(&R, &in_buff[j+half_block], half_block);
		Blowfish_Encrypt(&cipher, &L, &R);
		memcpy(&out_buff[j], &L, half_block);
		memcpy(&out_buff[j+half_block], &R, half_block);
	}
	
	/* writing header */
	cryptfile = fopen(argv[1], "wb");
	rewind(cryptfile);
	fwrite(&header, sizeof(header), 1, cryptfile);
	fclose(cryptfile);

	/* writing data */
	cryptfile = fopen(argv[1], "ab");
	fwrite(out_buff, sizeof(char), result, cryptfile);
	fclose(cryptfile);
	
	free(in_buff);
	free(out_buff);
}