#pragma once

#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include "util.h"
#include "tlv_utils.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>

// ----------------------
// --- Crypto Helpers ---

void print_pub_key(){
    if(public_key != NULL){
        print_hash("Current Public Key: ", public_key, pub_key_size);
    }
}

void derive_enc_keys(tlv* ch_tlv, tlv* sh_tlv){
    tlv* tlv_hellos[2] = {ch_tlv, sh_tlv};
    container salt = serialize_tlv_list(tlv_hellos, 2);
    print_hash("ENC keys salt: ", salt.data, salt.size);
    derive_keys(salt.data, salt.size);
    fprintf(stderr, "keys done\n");
}

container get_digest_of_tlv_list(tlv* tlv_list[], size_t tlv_count){
    container src_data = serialize_tlv_list(tlv_list, tlv_count);
    container result = new_container();
    hmac(result.data, src_data.data, src_data.size);
    result.size = MAC_SIZE;
    return result;
}

size_t get_plaintext_size(size_t length){
    return ((length - 60) / 16) * 16 - 1;
}