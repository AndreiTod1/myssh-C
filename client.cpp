#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#define SIZE 4096
#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16

void error(const char* text) {
    perror(text);
    exit(2);
}

int readAll(int sock, unsigned char* buffer, int length) {
    int total_read = 0;
    while (total_read < length) {
        int r = read(sock, buffer + total_read, length - total_read);
        if (r <= 0) {
            return -1;
        }
        total_read += r;
    }
    return total_read;
}

int writeAll(int sock, const unsigned char* buffer, int length) {
    int total_written = 0;
    while (total_written < length) {
        int w = write(sock, buffer + total_written, length - total_written);
        if (w <= 0) {
            return -1; 
        }
        total_written += w;
    }
    return total_written;
}

int initRsa(int sd, unsigned char aes_key[AES_KEY_LENGTH]) {

    uint32_t pem_length = 0;
    if (readAll(sd, (unsigned char*)&pem_length, sizeof(pem_length)) < 0) {
        error("[client] Eroare la citire (rsa key len).\n");
    }
    int pem_len = ntohl(pem_length);
    if (pem_len <= 0 || pem_len > 100000) {
        error("[client] Lungime PEM invalida.\n");
        return -1;
    }

    char* pem_data = new char[pem_len + 1];
    memset(pem_data, 0, pem_len + 1);
    if (readAll(sd, (unsigned char*)pem_data, pem_len) < 0) {
        error("[client] Eroare la citirea cheii publice.\n");
    }

    // rsa din pam
    BIO* bio = BIO_new_mem_buf(pem_data, pem_len);
    RSA* rsa_server_pubkey = PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL);
    if (!rsa_server_pubkey) {
        BIO_free(bio);
        delete[] pem_data;
        error("[client] Eroare la parsarea cheii publice.\n");
    }
    BIO_free(bio);
    delete[] pem_data;

    if (RAND_bytes(aes_key, AES_KEY_LENGTH) != 1) {
        perror("[client] Eroare la generarea cheii AES.\n");
        RSA_free(rsa_server_pubkey);
        return -1;
    }

    int rsa_size = RSA_size(rsa_server_pubkey);
    unsigned char* encrypted_aes = new unsigned char[rsa_size];

    int enc_len = RSA_public_encrypt(
                      AES_KEY_LENGTH,
                      aes_key,
                      encrypted_aes,
                      rsa_server_pubkey,
                      RSA_PKCS1_OAEP_PADDING);
    if (enc_len <= 0) {
        perror("[client] Eroare la encrypt.\n");
        RSA_free(rsa_server_pubkey);
        delete[] encrypted_aes;
        return -1;
    }

    if (writeAll(sd, encrypted_aes, enc_len) < 0) {
        RSA_free(rsa_server_pubkey);
        delete[] encrypted_aes;
        error("[client] Eroare la write (aes key).\n");

    }

    RSA_free(rsa_server_pubkey);
    delete[] encrypted_aes;
    return 0;
}

int main(int argc, char *argv[])
{
    int sd;
    struct sockaddr_in server;
    char command[SIZE];

    if (argc != 3) {
        printf("[client] Sintaxa: %s <adresa_server> <port>\n", argv[0]);
        return -1;
    }

    int port = atoi(argv[2]);
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd == -1) {
        perror("[client] Eroare la socket().\n");
        return errno;
    }

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(argv[1]);
    server.sin_port = htons(port);

    if (connect(sd, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("[client] Eroare la connect().\n");
        close(sd);
        return errno;
    }

    unsigned char aes_key[AES_KEY_LENGTH];
    if (initRsa(sd, aes_key) < 0) {
        perror("[client] Eroare initRsa()\n");
        close(sd);
        return -1;
    }

    printf("Cheia de criptare: %s\n", aes_key);

    AES_KEY enc_key;
        if (AES_set_encrypt_key(aes_key, AES_KEY_LENGTH * 8, &enc_key) < 0) {
            perror("[client] Eroare la encrypt key.\n");
        }

    while (true) {
        bzero(command, SIZE);
        printf("[client] Introduceti o comanda: ");
        fflush(stdout);

        if(!fgets(command, SIZE, stdin)) {
            break;
        }

        
        unsigned char init_vector[AES_BLOCK_SIZE];
        if (RAND_bytes(init_vector, AES_BLOCK_SIZE) != 1) {
            perror("[client] Eroare la generarea init vector.\n");
            break;
        }

        int cmd_len = strlen(command);
        int new_len = ((cmd_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
        unsigned char* plain_buf = new unsigned char[new_len];
        memset(plain_buf, 0, new_len);
        memcpy(plain_buf, command, cmd_len);

        unsigned char iv_enc[AES_BLOCK_SIZE];
        memcpy(iv_enc, init_vector, AES_BLOCK_SIZE);

        unsigned char* encrypted_command = new unsigned char[new_len];
        AES_cbc_encrypt(
            plain_buf,
            encrypted_command,
            new_len,
            &enc_key,
            iv_enc,
            AES_ENCRYPT
        );

        if (writeAll(sd, init_vector, AES_BLOCK_SIZE) < 0) {
            perror("[client] Eroare la write (init vector).\n");
            delete[] plain_buf; 
            delete[] encrypted_command;
            break;
        }

        int enc_len = htonl(new_len);
        if (writeAll(sd, (unsigned char*)&enc_len, sizeof(enc_len)) < 0) {
            perror("[client] Eroare la write (lungime).\n");
            delete[] plain_buf; 
            delete[] encrypted_command;
            break;
        }

        if (writeAll(sd, encrypted_command, new_len) < 0) {
            perror("[client] Eroare la write (comanda criptata).\n");
            delete[] plain_buf;  
            delete[] encrypted_command;
            break;
        }

        delete[] plain_buf;
        delete[] encrypted_command;
        
        unsigned char server_iv[AES_BLOCK_SIZE];
        if (readAll(sd, server_iv, AES_BLOCK_SIZE) < 0) {
            perror("[client] Eroare la read(init vector de la server).\n");
            break;
        }

        int enc_length = 0;
        if (readAll(sd, (unsigned char*)&enc_length, sizeof(enc_length)) < 0) {
            perror("[client] Eroare la read (raspuns).\n");
            break;
        }
        int dec_len = ntohl(enc_length);
        if (dec_len < 0) {
            printf("[client] Server inchis.\n");
            break;
        }

        unsigned char* encrypted_response = new unsigned char[dec_len];
        if (readAll(sd, encrypted_response, dec_len) < 0) {
            perror("[client] Eroare la read (rasp server).\n");
            delete[] encrypted_response;
            break;
        }

        AES_KEY dec_key;
        if (AES_set_decrypt_key(aes_key, AES_KEY_LENGTH*8, &dec_key) < 0) {
            perror("[client] Eroare la decrypt key.\n");
            delete[] encrypted_response;
            break;
        }
        unsigned char iv_dec[AES_BLOCK_SIZE];
        memcpy(iv_dec, server_iv, AES_BLOCK_SIZE);
        unsigned char* decrypted_response = new unsigned char[dec_len + 1];
        memset(decrypted_response, 0, dec_len + 1);

        AES_cbc_encrypt(
            encrypted_response,
            decrypted_response,
            dec_len,
            &dec_key,
            iv_dec,
            AES_DECRYPT
        );
        printf("[Server]: %s\n", decrypted_response);
        fflush(stdout);


        if (strcmp((char*)decrypted_response, "exit") == 0) {
            printf("EXITING client.\n");
            delete[] decrypted_response;
            delete[] encrypted_response;
            break;
        }

        delete[] decrypted_response;
        delete[] encrypted_response;
    }

    close(sd);
    return 0;
}
