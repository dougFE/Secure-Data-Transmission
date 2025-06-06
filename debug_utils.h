#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

// ----------------------------|
// Generic Debugging Utilities |
// ----------------------------|

// Make assertion, if it's false, exit with given code after sending debug message
void assert(bool assertion, int exit_code, char* debug_message){
    if(assertion) return;
    if(debug_message != NULL) fprintf(stderr, "%s\n", debug_message);
    exit(exit_code);
}

// Get printable string with first n bytes of a hash of the contents buf
// Good for identifying mismatched data between server and client. (Don't forget to free the returned pointer)
char* get_hash_str(uint8_t* buf, size_t len, size_t desired_hash_len){    
    assert(buf != NULL, -1, "Tried to compute hash of null buffer");
    desired_hash_len = MAX(SHA_DIGEST_LENGTH, desired_hash_len);
    
    // Calculate hash over buffer
    SHA_CTX sha_context;
    unsigned char digest[SHA_DIGEST_LENGTH];
    SHA1_Init(&sha_context);
    SHA1_Update(&sha_context, buf, len);
    SHA1_Final(digest, &sha_context);

    // stringified hash needs 3 chars per hash byte (2 hex chars + 1 space), and 1 for the null terminator
    char* hash_str = (char*)calloc(1, desired_hash_len * 3 + 1);
    // Truncate hash and convert to hexadecimal
    int hash_str_size = 0;
    for(int i = 0; i < desired_hash_len; i++){
        hash_str_size += sprintf(hash_str + hash_str_size, "%02x ", digest[i]);
    }
    return hash_str;
}

// Print a debug message with prefix followed by hash of a buffer
void print_hash(uint8_t* buf, size_t len, size_t hash_len, char* prefix){
    if(prefix != NULL) fprintf(stderr, "%s", prefix);
    char* hash = get_hash_str(buf, len, hash_len);
    fprintf(stderr, "%s\n", hash);
    free(hash);
}

// Check if two buffers are identical
bool compare_bytes(uint8_t* a, size_t size_a, uint8_t* b, size_t size_b){
    if(size_a != size_b) {
        fprintf(stderr, "Different size buffers\n");
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

// -----------------------|
// TLV-Specific Utilities |
// -----------------------|
#define MAX_PAYLOAD 1012
#define PAD_UNIT "|   "
#define DEFAULT_HASH_PREVIEW_LENGTH 2  // Recommended value

// Given a tlv, return a string representing its type
char* get_tlv_type_string(tlv* x)
{
    switch(x->type){
        case CLIENT_HELLO: return "CLIENT_HELLO";
        case NONCE: return "NONCE";
        case PUBLIC_KEY: return "PUBLIC_KEY";
        case CERTIFICATE: return "CERTIFICATE";
        case DNS_NAME: return "DNS_NAME";
        case SIGNATURE: return "SIGNATURE";
        case SERVER_HELLO: return "SERVER_HELLO";
        case HANDSHAKE_SIGNATURE: return "HANDSHAKE_SIGNATURE";
        case FINISHED: return "FINISHED";
        case TRANSCRIPT: return "TRANSCRIPT";
        case DATA: return "DATA";
        case IV: return "IV";
        case CIPHERTEXT: return "CIPHERTEXT";
        default: 
            fprintf(stderr, "Unrecognized TLV type: %d\n", x->type);
            exit(-1);
    }
}

// Print a short hash of a tlv, useful for quickly identifying small differences anywhere in the tlv
void print_tlv_hash(tlv* target, char* prefix){
    uint8_t tlv_buf[MAX_PAYLOAD];
    size_t tlv_size = serialize_tlv(tlv_buf, target);
    print_hash(tlv_buf, tlv_size, DEFAULT_HASH_PREVIEW_LENGTH, prefix);
}

// Recursion helper. Use "print_tlv_summary()" below to get readable summary of a tlv
void print_tlv_helper(tlv* target, int depth){
    for(int i = 0; i < depth; i++){  // Add padding first
        fprintf(stderr, "%s", PAD_UNIT);
    }
    if(target == NULL){
        fprintf(stderr, "TLV IS NULL\n");
        return;
    }

    int num_children = 0; // Count number of child TLV's
    for(int i = 0; target->children[i] != NULL; i++){
        num_children++;
    }

    // Print header line
    fprintf(stderr, "%s, LENGTH: %d, CHILDREN %d", get_tlv_type_string(target), target->length, target->children);
    
    if(num_children == 0){ // If no children, display hash of tlv->val
        print_hash(target->val, target->length, DEFAULT_HASH_PREVIEW_LENGTH, "VAL HASH: ");
    }
    else{  // If tlv does have children, display hash of the entire serialized tlv
        print_tlv_hash(target, "HASH: "); 
        for(int i = 0; i < num_children; i++){  // Print nested summaries of all children
            print_tlv_helper(target->children[i], depth + 1);
        }
    }
}

// Print a formatted summary of a tlv message and all it's children
void print_tlv_summary(tlv* target, char* debug_message){
    if(debug_message != NULL) fprintf(stderr, "%s\n", debug_message);
    print_tlv_helper(target, 0);
    fprintf(stderr, "\n");  
}
