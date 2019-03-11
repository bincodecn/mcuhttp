echo "Create server.key"
openssl genrsa -des3 -out server.key 2048

echo "Create CSR"
openssl req -new -key server.key -out server.csr

echo "Remove password"

cp server.key server.key.org
openssl rsa -in server.key.org -out server.key

echo "Create server.crt"
openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt
