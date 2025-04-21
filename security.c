#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include "util.h"
#include "tlv_utils.h"
#include "crypto_utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Handshake variables
int ch_len = 0;

tlv* ch_tlv = NULL;
tlv* sh_tlv = NULL;
tlv* client_finish_tlv = NULL;

bool hello_sent = false;
bool handshake_finished = false;

// Init variable storage
bool self_type;
char* hostname;

void init_sec(int type, char* host) {
    hostname = host;
    self_type = type;

    if(type == SERVER) fprintf(stderr, "Server starting\n");        
    if(type == CLIENT) fprintf(stderr, "Client starting. Hostname: %s\n", hostname);

    generate_private_key();
    derive_public_key();
    print_pub_key();
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if(!handshake_finished){    // Handshake Stage
        if(self_type == CLIENT){
            if(!hello_sent){ // Send client handshake
                ch_tlv = assert_not_null(build_client_hello());
                //print_tlv_summary(ch_tlv, "Sending client hello");
                hello_sent = true;
                return(serialize_tlv(buf, ch_tlv));
            }
            else if(client_finish_tlv != NULL){ // Send finished message
                handshake_finished = true;
                fprintf(stderr, "Handshake complete\n");
                return(serialize_tlv(buf, client_finish_tlv));
            }
        }
        if(self_type == SERVER){
            if(!hello_sent){
                if(sh_tlv != NULL){ // If hello message ready and not sent, send it
                    hello_sent = true;
                    print_tlv_summary(sh_tlv, "\n\nSending server hello!");
                    size_t output_size = serialize_tlv(buf, sh_tlv);
                    return(output_size);
                }
            }
        }
        return 0;
    }
    else{  // Data Stage
        // Get input from io layer
        uint8_t plaintext[MAX_PAYLOAD];
        size_t pt_size = input_io(plaintext, get_plaintext_size(max_length));

        // Encrypt that shi
        uint8_t iv[IV_SIZE];
        uint8_t ctext[MAX_PAYLOAD];
        size_t ctext_size = encrypt_data(iv, ctext, plaintext, pt_size);
        
        // Build data tlv
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, build_valued_tlv(IV, iv, IV_SIZE));
        add_tlv(data_tlv, build_valued_tlv(CIPHERTEXT, ctext, ctext_size));

        tlv* src_tlvs[2] = {get_tlv(data_tlv, IV), get_tlv(data_tlv, CIPHERTEXT)};
        container mac_con = get_digest_of_tlv_list(src_tlvs, 2);
        add_tlv(data_tlv, build_valued_tlv(MAC, mac_con.data, MAC_SIZE));

        return(serialize_tlv(buf, data_tlv));
    }
}

void output_sec(uint8_t* buf, size_t length) {
    tlv* recv_tlv = deserialize_tlv(buf, length);
    if(recv_tlv == NULL) return;
    if(!handshake_finished){
        if(self_type == SERVER){
            if(!hello_sent){
                // Recieve client hello
                assert_tlv_ptr(recv_tlv, recv_tlv->type == CLIENT_HELLO, UNEXPECTED_MSG, "Expected client hello");
                ch_tlv = recv_tlv;

                // Get client pubkey and derive shared secret
                tlv* client_pubkey = assert_not_null(get_tlv(ch_tlv, PUBLIC_KEY));
                print_hash("Recieved client pubkey: ", client_pubkey->val, client_pubkey->length);
                load_peer_public_key(client_pubkey->val, client_pubkey->length);
                derive_secret();
                fprintf(stderr, "secret finished\n");

                // Construct server hello
                sh_tlv = build_server_hello(ch_tlv);

                // Derive keys
                print_tlv_summary(ch_tlv, "ch_tlv");
                print_tlv_summary(sh_tlv, "sh_tlv");
                derive_enc_keys(ch_tlv, sh_tlv);
            }
            else{
                // Recieve client finished 
                assert_tlv_ptr(recv_tlv, recv_tlv->type == FINISHED, UNEXPECTED_MSG, "Server sent hello, received non-finished msg");
                assert_tlv_ptr(recv_tlv, get_tlv(recv_tlv, TRANSCRIPT) != NULL, UNEXPECTED_MSG, "Client finish doesn't include transcript");

                // Get client transcript
                tlv* cl_ts_tlv = get_tlv(recv_tlv, TRANSCRIPT);

                // Calculate own transcript
                tlv* ts_src_tlvs[2] = {ch_tlv, sh_tlv};
                container sv_ts = get_digest_of_tlv_list(ts_src_tlvs, 2);

                bool transcripts_match = compareBytes(cl_ts_tlv->val, cl_ts_tlv->length, sv_ts.data, sv_ts.size);
                print_hash("Server's transcript: ", sv_ts.data, sv_ts.size);
                assert_tlv_ptr(recv_tlv, transcripts_match, BAD_TRANSCRIPT, "Transcipts don't match");
                handshake_finished = true;
                fprintf(stderr, "Transcripts matched, handshake complete\n");
            }

        }
        if(self_type == CLIENT){
            if(hello_sent){
                // Recieve server hello
                assert_tlv_ptr(recv_tlv, recv_tlv->type == SERVER_HELLO, UNEXPECTED_MSG, "Expected server hello");
                sh_tlv = recv_tlv; // Received server hello. Cache it and work on response
                tlv* sh_nonce = assert_not_null(get_tlv(sh_tlv, NONCE));
                tlv* sh_pubkey = assert_not_null(get_tlv(sh_tlv, PUBLIC_KEY));
                tlv* sh_hs_sign = assert_not_null(get_tlv(sh_tlv, HANDSHAKE_SIGNATURE));
                tlv* sh_cert = assert_not_null(get_tlv(sh_tlv, CERTIFICATE));
                tlv* sh_dns = assert_not_null(get_tlv(sh_cert, DNS_NAME));
                tlv* sh_cert_pubkey = assert_not_null(get_tlv(sh_cert, PUBLIC_KEY));
                tlv* sh_cert_sign = assert_not_null(get_tlv(sh_cert, SIGNATURE));

                // Verify certificate
                tlv* src_tlvs[2] = {sh_dns, sh_cert_pubkey};
                container sign_data = serialize_tlv_list(src_tlvs, 2);
                load_ca_public_key(CA_PUBLIC_KEY_PATH);
                bool cert_valid = verify(sh_cert_sign->val, sh_cert_sign->length, sign_data.data, sign_data.size, ec_ca_public_key);
                assert_tlv_ptr(sh_tlv, cert_valid, BAD_CERTIFICATE, "Server hello has invalid certificate");
                
                // Verify DNS name 
                bool dns_match = compareBytes((uint8_t*)hostname, strlen(hostname), sh_dns->val, strlen((char*)sh_dns->val));
                assert_tlv_ptr(sh_tlv, dns_match, BAD_DNS, "Server hello has wrong DNS");

                // Verify server_hello handshake signature
                tlv* hs_src_tlvs[4] = {ch_tlv, sh_nonce, sh_cert, sh_pubkey};
                container hs_data = serialize_tlv_list(hs_src_tlvs, 4);

                print_hash("HandSake Signature source data: ", hs_data.data, hs_data.size);


                load_peer_public_key(sh_cert_pubkey->val, sh_cert_pubkey->length); // Get pubkey from certificate

                bool hs_valid = verify(sh_hs_sign->val, sh_hs_sign->length, hs_data.data, hs_data.size, ec_peer_public_key);
                assert_tlv_ptr(sh_tlv, hs_valid, BAD_SIGNATURE, "Server hello has invalid handshake signature");
                //print_tlv_summary(sh_tlv, "Server hello recieved and verified!");

                print_hash("Handshake sign verified. Peer key is currently: ", (uint8_t*)ec_peer_public_key, EVP_PKEY_size(ec_peer_public_key));

                // Server hello verified. Derive keys
                load_peer_public_key(sh_pubkey->val, sh_pubkey->length); // Load server's ephemeral key as peer key
                print_hash("Recieved server pubkey: ", sh_pubkey->val, sh_pubkey->length);
                derive_secret();
                fprintf(stderr, "secret finished\n");
                
                print_tlv_hash(ch_tlv, "ch_tlv");
                print_tlv_hash(sh_tlv, "sh_tlv");
                derive_enc_keys(ch_tlv, sh_tlv);

                // Calculate transcript
                tlv* ts_src_tlvs[2] = {ch_tlv, sh_tlv};
                container cl_ts = get_digest_of_tlv_list(ts_src_tlvs, 2);
                print_hash("Client's Transcript: ", cl_ts.data, cl_ts.size);

                // Build client finished message
                tlv* transcript_tlv = build_valued_tlv(TRANSCRIPT, cl_ts.data, cl_ts.size);
                client_finish_tlv = create_tlv(FINISHED);
                add_tlv(client_finish_tlv, transcript_tlv);
            }
        }
        return;
    }
    else{
        // Verify valid data tlv:
        assert_tlv_ptr(recv_tlv, recv_tlv->type == DATA, UNEXPECTED_MSG, "Non-data packet after handshake");
        tlv* iv = assert_not_null(get_tlv(recv_tlv, IV));
        tlv* ctext = assert_not_null(get_tlv(recv_tlv, CIPHERTEXT));
        tlv* mac = assert_not_null(get_tlv(recv_tlv, MAC));
        tlv* src_tlvs[2] = {iv, ctext};
        container my_digest = get_digest_of_tlv_list(src_tlvs, 2);

        print_hash("Client's digest: ", my_digest.data, my_digest.size);
        print_hash("Server's Digest: ", mac->val, mac->length);

        assert(compareBytes(my_digest.data, my_digest.size, mac->val, mac->length), BAD_MAC, "Invalid MAC recieved");

        // Decrypt and output data
        size_t output_bytes = decrypt_cipher(buf, ctext->val, ctext->length, iv->val);
        output_io(buf, output_bytes);
    }
}
