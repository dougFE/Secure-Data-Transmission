#pragma once

#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

// Custom constants
#define MAX_TLV_HEADER_SIZE 4
#define MAX_SIGNATURE_SIZE 72
#define MAX_PAYLOAD 1012
#define MAX_SRC_DATA_SIZE MAX_PAYLOAD * 3
#define HASH_LEN 2
#define CONTAINER_SIZE MAX_SRC_DATA_SIZE

// Debugging 
#define PAD_UNIT "|       "

// File paths
#define PRIV_KEY_PATH "server_key.bin"
#define CA_PUBLIC_KEY_PATH "ca_public_key.bin"
#define CERTIFICATE_PATH "server_cert.bin"

// Exit statuses
#define BAD_CERTIFICATE 1
#define BAD_DNS 2
#define BAD_SIGNATURE 3
#define BAD_TRANSCRIPT 4
#define BAD_MAC 5
#define UNEXPECTED_MSG 6
#define ERR -1

// -------------------------
// --- Generic Utilities ---

typedef struct container{
    uint8_t data[CONTAINER_SIZE];
    size_t size;
} container;

container new_container(){
    container result;
    result.size = 0;
    for(int i = 0; i < CONTAINER_SIZE; i++) result.data[i] = 0;
    return result;
}

bool compareBytes(uint8_t* a, size_t size_a, uint8_t* b, size_t size_b){
    if(size_a != size_b) {
        fprintf(stderr, "diff size\n");
        return false;
    }
    for(size_t i = 0; i < size_a; i++){
        if(a[i] != b[i]) {
            fprintf(stderr, "Bytes %ld differ\n", i);
            return false;
        }
    }
    return true;
}

// -------------------------
// --- Debugging Methods ---

void assert(bool assertion, int exit_code, char* debug_message){
    if(!assertion){
        fprintf(stderr, "%s\n", debug_message);
        exit(exit_code);
    }
}

// Make a short string hash of a buffer, used for quick comparisons between server and client
char* get_hash_str(uint8_t* buf, size_t len){    
    assert(SHA_DIGEST_LENGTH >= HASH_LEN, ERR, "Hash len too big");
    
    // stringified hash needs 3 chars per hash byte (2 hex and 1 space), and 1 for the null terminator
    char* hash_str = calloc(1, HASH_LEN* 3 + 1);
    if(buf == NULL){
        sprintf(hash_str, "[ NULL HASH ]");
        return(hash_str);
    }
    
    // Calculate hash over buffer
    SHA_CTX sha_context;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Init(&sha_context);
    SHA1_Update(&sha_context, buf, len);
    SHA1_Final(digest, &sha_context);

    // Truncate hash to fit in hash_string
    int hash_str_size = 0;
    for(int i = 0; i < HASH_LEN; i++){
        hash_str_size += sprintf(hash_str + hash_str_size, "%02x ", digest[i]);
    }
    return hash_str;
}

// Print a debug message with prefix followed by hash of a buffer
void print_hash(char* prefix, uint8_t* buf, size_t len){
    if(prefix != NULL) fprintf(stderr, "%s", prefix);
    char* hash = get_hash_str(buf, len);
    fprintf(stderr, "%s\n", hash);
    free(hash);
}

// Wrap all pointers in this for null checks
void* assert_not_null(void* target){
    if(target == NULL){
        fprintf(stderr, "Failed not-null assertion\n");
        exit(ERR);
    }
    return target;
}