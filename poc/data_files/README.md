## Generate
```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout ca.key -out ca.crt -days 365 -subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=Test CA" -addext "subjectAltName = DNS:localhost"

openssl req -new -newkey rsa:4096 -nodes -keyout server.key -out server.csr -subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=localhost"
openssl x509 -req -extfile <(printf "subjectAltName=DNS:localhost") -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

openssl req -new -newkey rsa:4096 -nodes -keyout client.key -out client.csr -subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=client"
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```
