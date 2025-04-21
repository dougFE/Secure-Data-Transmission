#pragma once

#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include "util.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>


// --------------------------
// --- TLV HELPER METHODS ---

char* get_tlv_type_string(tlv* x)
{
    if(x->type == CLIENT_HELLO) return "CLIENT_HELLO";
    if(x->type == NONCE) return "NONCE";
    if(x->type == PUBLIC_KEY) return "PUBLIC_KEY";
    if(x->type == CERTIFICATE) return "CERTIFICATE";
    if(x->type == DNS_NAME) return "DNS_NAME";
    if(x->type == SIGNATURE) return "SIGNATURE";
    if(x->type == SERVER_HELLO) return "SERVER_HELLO";
    if(x->type == HANDSHAKE_SIGNATURE) return "HANDSHAKE_SIGNATURE";
    if(x->type == FINISHED) return "FINISHED";
    if(x->type == TRANSCRIPT) return "TRANSCRIPT";
    if(x->type == DATA) return "DATA";
    if(x->type == IV) return "IV";
    if(x->type == CIPHERTEXT) return "CIPHERTEXT";
    if(x->type == MAC) return "MAC";
    fprintf(stderr, "Unrecognized TLV type: %d\n", x->type);
    exit(6);
}

void print_tlv_hash(tlv* target, char* prefix){
    uint8_t tlv_buf[MAX_PAYLOAD];
    size_t tlv_size = serialize_tlv(tlv_buf, target);
    print_hash(prefix, tlv_buf, tlv_size);
}

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
    fprintf(stderr, "%s, ", get_tlv_type_string(target));
    fprintf(stderr, "LENGTH: %d, ", target->length);
    fprintf(stderr, "CHILDREN: %d, ", num_children);
    
    // If no children, add a line to show a hashed val preview
    if(num_children == 0){ 
        print_hash("VAL HASH: ", target->val, target->length);
    }
    else{
        print_tlv_hash(target, "TLV HASH: ");
        // Recurse on all children
        for(int i = 0; i < num_children; i++){
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

// If assertion fails, exit with the proper code and debug message
void assert_tlv_ptr(tlv* target, bool assertion, int exit_code, char* debug_message){
    bool always_print = false; // Set to true for all asserts to print summaries without the debug message
    if(!assertion){
        print_tlv_summary(target, debug_message);
        exit(exit_code);
    }
    else if(always_print) print_tlv_summary(target, NULL);
    
}

static inline tlv* build_valued_tlv(uint8_t type, uint8_t* val, uint16_t size){
    tlv* t = create_tlv(type);
    add_val(t, val, size);
    return t;
}

// Given a list of tlvs, serialize them in the order given to data_buf
container serialize_tlv_list(tlv* tlvs[], int num_tlvs){
    container result = new_container();
    for(int i = 0; i < num_tlvs && tlvs[i] != NULL; i++){
        assert_tlv_ptr(tlvs[i], result.size + tlvs[i]->length + MAX_TLV_HEADER_SIZE <= CONTAINER_SIZE, ERR, "Buffer too small for serialize_tlv_list!");
        result.size += serialize_tlv(result.data + result.size, tlvs[i]);
    }
    return result;
}

tlv* build_nonce_tlv(){
    uint8_t nonce[NONCE_SIZE];
    generate_nonce(nonce, NONCE_SIZE);
    return build_valued_tlv(NONCE, nonce, NONCE_SIZE);
}

// Build server hello
tlv* build_server_hello(tlv* ch_tlv){
    tlv* hello_tlv = create_tlv(SERVER_HELLO);
    // Nonce
    add_tlv(hello_tlv, build_nonce_tlv()); 

    // Server certificate
    load_certificate(CERTIFICATE_PATH);
    tlv* cert_tlv = deserialize_tlv(certificate, cert_size);
    add_tlv(hello_tlv, cert_tlv);

    // Public key
    tlv* pubkey_tlv = build_valued_tlv(PUBLIC_KEY, public_key, pub_key_size);
    add_tlv(hello_tlv, pubkey_tlv);

    // Handshake signature
    tlv* src_tlvs[4] = {ch_tlv, get_tlv(hello_tlv, NONCE), cert_tlv, pubkey_tlv};
    container sign_data = serialize_tlv_list(src_tlvs, 4);
    print_hash("HS Signature source data: ", sign_data.data, sign_data.size);
    
    EVP_PKEY* eph_private = get_private_key();
    load_private_key(PRIV_KEY_PATH); // Switch to static private key
    uint8_t signature[MAX_SIGNATURE_SIZE];
    size_t sign_size = sign(signature, sign_data.data, sign_data.size);
    tlv* sign_tlv = build_valued_tlv(HANDSHAKE_SIGNATURE, signature, sign_size);
    add_tlv(hello_tlv, sign_tlv);
    set_private_key(eph_private); // Switch back to ephemeral key
    return hello_tlv;
}

tlv* build_client_hello(){
    tlv* hello_tlv = create_tlv(CLIENT_HELLO);
    // Nonce
    add_tlv(hello_tlv, build_nonce_tlv()); 

    // Public key
    tlv* public_key_tlv = build_valued_tlv(PUBLIC_KEY, public_key, pub_key_size);
    add_tlv(hello_tlv, public_key_tlv);
    return hello_tlv;
}
