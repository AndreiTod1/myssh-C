#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <wait.h>

#include <iostream>
#include <vector>
#include <string.h>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>   
#include <sqlite3.h> 

#include "exec.cpp"

using namespace std;

#define PORT 2025
#define SIZE 4096
#define MAX_CLIENTS 200
#define RSA_KEY_LENGTH 2048
#define AES_KEY_LENGTH 32
#define AES_BLOCK_SIZE 16

vector<string> client_paths(MAX_CLIENTS, "/");
vector<unsigned char> client_aes_keys[MAX_CLIENTS];
bool isLoggedIn[MAX_CLIENTS];     
string currentUser[MAX_CLIENTS];  

struct sockaddr_in server_addr;
struct sockaddr_in from;
fd_set readfds;
fd_set actfds;
struct timeval tv;
int sd, client;
int optval = 1;
int fd;
int nfds;
socklen_t len;
char server_path[PATH_MAX];

sqlite3 *database = nullptr;

void error(const char* text) {
    perror(text);
    exit(2);
}

char* conv_addr(struct sockaddr_in address) {
    char str[25];
    char port_str[7];
    strcpy(str, inet_ntoa(address.sin_addr));	
    bzero(port_str, 7);
    sprintf(port_str, ":%d", ntohs(address.sin_port));	
    strcat(str, port_str);
    return str;
}

std::string sha256(const std::string &data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)data.c_str(), data.size(), hash);

    char buf[2 * SHA256_DIGEST_LENGTH + 1];
    buf[2 * SHA256_DIGEST_LENGTH] = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(buf + i*2, "%02x", hash[i]);
    }
    return std::string(buf);
}

std::string generateSalt(size_t length = 16) {
    const char chars[] =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";
    std::string salt;
    salt.reserve(length);

    srand((unsigned int)time(NULL));

    for (size_t i = 0; i < length; i++) {
        salt.push_back(chars[rand() % (sizeof(chars) - 1)]);
    }
    return salt;
}

bool exec(sqlite3* db, std::string sql) {
    char *err = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), 0, 0, &err);
    if (rc != SQLITE_OK) {
        printf("[SQLite] Eroare la open: %s", err);
        sqlite3_free(err);
        return false;
    }
    return true;
}

bool initDatabase(sqlite3** db) {
    int rc = sqlite3_open("users.db", db);
    if (rc != SQLITE_OK) {
        printf("[SQLite] Eroare la open: %s", sqlite3_errmsg(*db));
        return false;
    }

    std::string createTable = 
        "CREATE TABLE IF NOT EXISTS users ("
        "  username TEXT PRIMARY KEY,"
        "  salt TEXT NOT NULL,"
        "  password_hash TEXT NOT NULL"
        ");";

    return exec(*db, createTable);
}

bool registerUser(sqlite3* db, std::string &username, std::string &password) {
    std::string salt = generateSalt(16);
    std::string pass_hash = sha256(salt + password);

    char *sql = "INSERT INTO users (username, salt, password_hash) VALUES (?,?,?);";
    sqlite3_stmt *command = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &command, NULL) != SQLITE_OK) {
        printf("[SQLite] Eroare la prepare (register): %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(command, 1, username.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(command, 2, salt.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(command, 3, pass_hash.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(command);
    if (rc != SQLITE_DONE) {
        printf("[SQLite] Nu s-a putut insera userul %s\n %s", username, sqlite3_errmsg(db));
        sqlite3_finalize(command);
        return false;
    }
    sqlite3_finalize(command);
    return true;
}

bool loginUser(sqlite3* db, std::string &username, std::string &password) {
    char* sql = "SELECT salt, password_hash FROM users WHERE username=?;";
    sqlite3_stmt *command = nullptr;

    if (sqlite3_prepare_v2(db, sql, -1, &command, NULL) != SQLITE_OK) {
        printf("[SQLite] Eroare la prepare (login): %s", sqlite3_errmsg(db));
        return false;
    }
    sqlite3_bind_text(command, 1, username.c_str(), -1, SQLITE_TRANSIENT);

    int rc = sqlite3_step(command);
    if (rc == SQLITE_ROW) {
        const unsigned char* db_salt = sqlite3_column_text(command, 0);
        const unsigned char* db_passHash = sqlite3_column_text(command, 1);

        std::string salt_str((char*)db_salt);
        std::string passHash_str((char*)db_passHash);

        sqlite3_finalize(command);

        std::string localHash = sha256(salt_str + password);
        if (localHash == passHash_str) {
            return true;
        } else {
            return false;
        }
    }
    else {
        sqlite3_finalize(command);
        return false;
    }
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

int writeAll(int sock, unsigned char* buffer, int length) {
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

void handle_client(int fd) {
    
    unsigned char init_vector[AES_BLOCK_SIZE];
    int n = readAll(fd, init_vector, AES_BLOCK_SIZE);
    if(n < 0) {
        printf("Clientul %d s-a deconectat (eroare la citire IV).\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }

    int enc_len_net = 0;
    n = readAll(fd, (unsigned char*)&enc_len_net, sizeof(enc_len_net));
    if (n < 0) {
        printf("Clientul %d s-a deconectat (eroare la citire lungime comanda).\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }
    int enc_len = ntohl(enc_len_net);
    if(enc_len <= 0) {
        printf("Clientul %d a trimis 0 octeți -> deconectăm.\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }

    vector<unsigned char> encrypted_command(enc_len, 0);
    n = readAll(fd, encrypted_command.data(), enc_len);
    if(n < 0) {
        printf("Clientul %d s-a deconectat (eroare la citire comanda criptata).\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }

    AES_KEY dec_key;
    if(AES_set_decrypt_key(client_aes_keys[fd].data(), AES_KEY_LENGTH * 8, &dec_key) < 0) {
        perror("Eroare la AES_set_decrypt_key");
        return;
    }
    vector<unsigned char> decrypted_command(enc_len, 0);
    unsigned char vector_copy[AES_BLOCK_SIZE];
    memcpy(vector_copy, init_vector, AES_BLOCK_SIZE);

    AES_cbc_encrypt(
        encrypted_command.data(),
        decrypted_command.data(),
        enc_len,
        &dec_key,
        vector_copy,
        AES_DECRYPT
    );

    string input((char*)decrypted_command.data(), enc_len);
    while(!input.empty() && (input.back() == '\n' || input.back() == '\0')) {
        input.pop_back();
    }
    string output;

    if (!isLoggedIn[fd]) {
        vector<string> tokens;
        {
            string temp;
            for (char c : input) {
                if (c == ' ') {
                    if (!temp.empty()) {
                        tokens.push_back(temp);
                        temp.clear();
                    }
                } else {
                    temp.push_back(c);
                }
            }
            if (!temp.empty()) tokens.push_back(temp);
        }

        if (tokens.size() == 3 && tokens[0] == "login") {
            string user = tokens[1];
            string pass = tokens[2];
            if (loginUser(database, user, pass)) {
                isLoggedIn[fd] = true;
                currentUser[fd] = user;
                output = "Autentificare reusita! [" + user + "]";
            } else {
                output = "User/parola incorecte.";
            }
        }
        else if (tokens.size() == 3 && tokens[0] == "register") {
            string user = tokens[1];
            string pass = tokens[2];
            if (registerUser(database, user, pass)) {
                output = "Cont creat! Acum puteti da login.";
            } else {
                output = "Eroare la crearea contului. (user deja existent)";
            }
        }
        else {
            output = "Nu ati efectuat logarea! Folositi: \n  login <user> <pass>\n  register <user> <pass>\n";
        }
    } 
    else {
        output = execution(input, fd, client_paths);
    }

    printf("[Server] Comanda primita de la clientul %d: %s\n", fd, input.c_str());
    fflush(stdout);
    printf("[Server] Raspuns: %s\n", output.c_str());
    fflush(stdout);

    int plain_len = output.size();
    int new_len = ((plain_len + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    vector<unsigned char> plain_buf(new_len, 0);
    memcpy(plain_buf.data(), output.data(), plain_len);

    unsigned char resp_iv[AES_BLOCK_SIZE];
    if (RAND_bytes(resp_iv, AES_BLOCK_SIZE) != 1) {
        perror("Eroare la generarea init vector pentru output");
        return;
    }

    AES_KEY enc_key;
    if(AES_set_encrypt_key(client_aes_keys[fd].data(), AES_KEY_LENGTH * 8, &enc_key) < 0) {
        perror("Eroare la encrypt (output)");
        return;
    }
    vector<unsigned char> encrypted_output(new_len, 0);

    unsigned char resp_iv_copy[AES_BLOCK_SIZE];
    memcpy(resp_iv_copy, resp_iv, AES_BLOCK_SIZE);

    AES_cbc_encrypt(
        plain_buf.data(),
        encrypted_output.data(),
        new_len,
        &enc_key,
        resp_iv_copy,
        AES_ENCRYPT
    );

    if (writeAll(fd, resp_iv, AES_BLOCK_SIZE) < 0) {
        printf("Eroare la write (init vector) pentru %d\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }
    int net_padded_len = htonl(new_len);
    if (writeAll(fd, (unsigned char*)&net_padded_len, sizeof(net_padded_len)) < 0) {
        printf(" Eroare la write (lungime) pentru %d\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }
    if (writeAll(fd, encrypted_output.data(), new_len) < 0) {
        printf("Eroare la write (output criptat) pentru %d\n", fd);
        close(fd);
        FD_CLR(fd, &actfds);
        return;
    }
}

int main () {
    if (realpath("./", server_path) == NULL) {  
        perror("Eroare: nu se poate obține server_path\n");
        exit(1);
    }
    string server_path_str = string(server_path);
    printf("Directorul serverului setat la: %s\n", server_path);
    fflush(stdout);


    for(int i = 0; i < MAX_CLIENTS; i++) {
        client_paths[i] = server_path_str;
        client_aes_keys[i].resize(AES_KEY_LENGTH, 0);
        isLoggedIn[i] = false;
        currentUser[i].clear();
    }

    if (!initDatabase(&database)) {
        cerr << "Eroare la initDatabase. Iesim.\n";
        exit(1);
    }


    RSA *rsa = RSA_new();
    BIGNUM *bn = BN_new();
    BN_set_word(bn, RSA_F4); 
    if (!RSA_generate_key_ex(rsa, RSA_KEY_LENGTH, bn, NULL)) {
        error("Eroare la generare cheie RSA\n");
    }
    BN_free(bn);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        error("Eroare la socket().\n");
    }
    setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    bzero(&server_addr, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr)) < 0) {
        error("Eroare la bind().\n");
    }
    
    if (listen(sd, 5) < 0) {
        error("Eroare la listen().\n");
    }
    
    FD_ZERO(&actfds);
    FD_SET(sd, &actfds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    nfds = sd;

    printf("Server deschis la portul: %d...\n", PORT);
    fflush(stdout);
            
    while (true) {
        readfds = actfds; 
        int select_ret = select(nfds+1, &readfds, NULL, NULL, &tv);
        if (select_ret < 0) {
            perror("Eroare la select().\n");
            continue;
        }

        if (FD_ISSET(sd, &readfds)) {
            len = sizeof(from);
            bzero(&from, sizeof(from));
            client = accept(sd, (struct sockaddr *)&from, &len);
            if (client < 0) {
                perror("Eroare la accept()");
                continue;
            }

            if (client >= MAX_CLIENTS) {
                cerr << "Nr maxim de clienti atins. User refuzat\n";
                close(client);
                continue;
            }

            
            isLoggedIn[client] = false;
            currentUser[client].clear();
            client_paths[client] = server_path_str;


            // trimit rsa            
            BIO* bio = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(bio, rsa);
            int pem_len = BIO_pending(bio);
            vector<char> pem_data(pem_len + 1, 0);
            BIO_read(bio, pem_data.data(), pem_len);
            pem_data[pem_len] = '\0';
            BIO_free(bio);

            uint32_t netPemLen = htonl(pem_len);
            if (writeAll(client, (unsigned char*)&netPemLen, sizeof(netPemLen)) < 0) {
                perror("Eroare la write (lungime pem) ");
                close(client);
                continue;
            }
            if (writeAll(client, (unsigned char*)pem_data.data(), pem_len) < 0) {
                perror("Eroare la write (pem) ");
                close(client);
                continue;
            }

            
            int rsa_size = RSA_size(rsa);
            vector<unsigned char> encrypted_aes(rsa_size, 0);
            int read_bytes = readAll(client, encrypted_aes.data(), rsa_size);
            if (read_bytes < 0) {
                perror("Eroare la read (aes key) ");
                close(client);
                continue;
            }

            unsigned char aes_key_buf[AES_KEY_LENGTH];
            int dec_len = RSA_private_decrypt(
                rsa_size,
                encrypted_aes.data(),
                aes_key_buf,
                rsa,
                RSA_PKCS1_OAEP_PADDING
            );
            if (dec_len <= 0) {
                perror("Eroare la decrypt aes");
                close(client);
                continue;
            }
            memcpy(client_aes_keys[client].data(), aes_key_buf, AES_KEY_LENGTH);

            if (nfds < client) {
                nfds = client;
            }
            FD_SET(client, &actfds);
            printf(" S-a conectat clientul (fd=%d), de la %s\n",client, conv_addr(from));
            fflush(stdout);

            printf("Cheia de criptare: %s\n", aes_key_buf);
        }

        for (fd = 0; fd <= nfds; fd++) {
            if (fd != sd && FD_ISSET(fd, &readfds)) {
                handle_client(fd);
            }
        }
    }

    RSA_free(rsa);
    sqlite3_close(database);
    close(sd);
    return 0;
}
