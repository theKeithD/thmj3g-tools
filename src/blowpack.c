/**
 * blowpack.c -- Run a file through a non-chaining Blowfish cipher and insert
 *               a bogus LZSS header for use with certain versions of AIMS.
 *               If a header already exists, the program will either ignore
 *               the file, or if the -d option is provided, it will strip
 *               the header and decrypt the data.
 *               The file will be overwritten, so be careful!
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
size_t read_bytes;

BLOWFISH_CTX cipher;
unsigned char blowfish_key[56];

char strip_header = 0; // if set to a non-zero value and the -d switch is
                       // given, strip LZSS header from file and decrypt 
                       // file instead.

uint32_t expected_magic = 0x53535A4C; // "LZSS" in little-endian form

typedef struct {
    uint32_t magic; // "LZSS"
    uint32_t size; // simply the filesize, for varying definitions of "simply"
} boguslzss;

/* Make sure the file we're encrypting/decrypting actually exists.
   Call this at the beginning of any function that uses that file.
 */
void check_handle() {
    if(cryptfile == NULL) {
        printf("FATAL: cryptfile handle not defined.\n");
        exit(EXIT_FAILURE);
    }
}

/* Initialize the Blowfish cipher.
 */
void prepare_cipher() {
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
}

/* Read the first 8 bytes of the file, and check if the first 4 bytes
 * matches the magic bytes "LZSS". Contrary to typical belief, it doesn't
 * signify an LZSS-compressed file, but an encrypted file. Fun, huh?
 */
char check_for_header() {
    check_handle();
    
    boguslzss head;

    rewind(cryptfile);
    fread(&head, sizeof(head), 1, cryptfile);

    if(head.magic == expected_magic) {
        return 1;
    }
    return 0;
}

/* Encrypt file using non-chaining Blowfish alogorithm. Prepends an LZSS
 * header containing the "LZSS" magic bytes as well as the file's size before
 * modification.
 */
void encrypt_file(char* filename) {
    check_handle();
    fclose(cryptfile);
    
    /* generate bogus LZSS header */
    boguslzss header;
    header.magic = expected_magic; // "LZSS"
    header.size = read_bytes; // non-padded value
    
    read_bytes = (read_bytes + 7) & ~7; // padding

    out_buff = (char*) malloc((sizeof(char) * read_bytes));
    
    /* ciphering */
    int half_block = sizeof(unsigned long);
    int j;
    unsigned long L, R;
    for(j=0; j<read_bytes; j+=(2*half_block)) {
        memcpy(&L, &in_buff[j], half_block);
        memcpy(&R, &in_buff[j+half_block], half_block);
        Blowfish_Encrypt(&cipher, &L, &R);
        memcpy(&out_buff[j], &L, half_block);
        memcpy(&out_buff[j+half_block], &R, half_block);
    }
    
    /* writing header */
    cryptfile = fopen(filename, "wb");
    rewind(cryptfile);
    fwrite(&header, sizeof(header), 1, cryptfile);
    fclose(cryptfile);

    /* writing data */
    cryptfile = fopen(filename, "ab");
    fwrite(out_buff, sizeof(char), read_bytes, cryptfile);
    fclose(cryptfile);
    
    free(in_buff);
    free(out_buff);
}

/* Strips out LZSS header and decrypts file using non-chaining Blowfish, 
 * producing a file with a size equal to the size field in the LZSS header.
 */
void strip_file(char* filename) {
    check_handle();
    
    /* read LZSS header */
    boguslzss head;
    rewind(cryptfile);
    fread(&head, sizeof(head), 1, cryptfile);
    fclose(cryptfile);
    
    out_buff = (char*) malloc((sizeof(char) * read_bytes));
    
    /* ciphering */
    int half_block = sizeof(unsigned long);
    int j;
    unsigned long L, R;
    for(j=sizeof(head); j<read_bytes; j+=(2*half_block)) {
        memcpy(&L, &in_buff[j], half_block);
        memcpy(&R, &in_buff[j+half_block], half_block);
        Blowfish_Decrypt(&cipher, &L, &R);
        memcpy(&out_buff[j-sizeof(head)], &L, half_block);
        memcpy(&out_buff[j-sizeof(head)+half_block], &R, half_block);
    }
    
    /* snipping end off */
    out_buff[head.size] = 0x00;
    
    /* writing data */
    cryptfile = fopen(filename, "wb");
    fwrite(out_buff, sizeof(char), head.size, cryptfile);
    fclose(cryptfile);
    
    free(in_buff);
    free(out_buff);
}

int main(int argc, char *argv[]) {
    if(argc <= 1) {
        printf("blowpack: Decrypt/encrypt files using non-chaining Blowfish algorithm and \n");
        printf("append/strip a bogus LZSS header as necessary.\n\n");
        printf("Usage: blowpack cryptfile [-d]\n");
        printf("-d: Strip LZSS header and decrypt file contents. No effect on files without \n");
        printf("    an LZSS header. Likewise, a file with an LZSS header and no -d option \n");
        printf("    will be ignored.\n");
        return EXIT_FAILURE;
    }

    /* read file in */
    if((cryptfile = fopen(argv[1], "rb")) == NULL) {
        printf("ERROR: %s could not be read or does not exist.\n", argv[1]);
        return EXIT_FAILURE;
    }
    
    strip_header = check_for_header();

    fseek(cryptfile, 0, SEEK_END);
    size_t filesize = ftell(cryptfile);

    in_buff = (char*) malloc((sizeof(char) * filesize));
    
    rewind(cryptfile);
    read_bytes = fread(in_buff, 1, filesize, cryptfile);


    if(read_bytes != filesize) {
        printf("  - WARNING: Expected %d bytes, only read %d bytes.\n", filesize, read_bytes);
    }
    
    if(argc >= 3) { // processing mode switch given
        if((strcmp(argv[2], "-d") == 0)) { // -d switch given
            if(strip_header == 0) {
                printf("-d switch given, but no LZSS header detected. Ignoring -d switch.\n");
            }
        } else { // invalid switch
            printf("Invalid processing mode, ignoring.\n");
            strip_header = 0; // disable stripping mode for an invalid switch
        }
    } else { // no switch given, perform strip_header checks
        if(strip_header != 0) {
            printf("LZSS header detected, but no -d switch given. Ignoring file.\n");
            strip_header = 0;
            return EXIT_FAILURE;
        }
    }
    
    
    prepare_cipher();
    
    if(strip_header == 0) {
        printf("Encrypting file and prepending header...\n");
        encrypt_file(argv[1]);
    } else {
        printf("Stripping header from file and decrypting...\n");
        strip_file(argv[1]);
    }
    
    return EXIT_SUCCESS;
}