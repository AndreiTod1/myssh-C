rm client
rm server



g++ server.cpp -o server -lssl -lcrypto -lsqlite3 
g++ client.cpp -o client -lssl -lcrypto