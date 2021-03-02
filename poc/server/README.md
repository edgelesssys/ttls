The required certificate chain and keys can be created as follows:
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 365 \
-subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=Test CA" \
-addext "subjectAltName = DNS:localhost"

openssl req -new -newkey rsa:4096 -nodes -keyout server.key -out server.csr -days 365 \
-subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=localhost" \
-addext "subjectAltName = DNS:localhost"

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

cat server.crt ca.crt > certs.pem
```

Then run the server:
```bash
go run server.go
```
