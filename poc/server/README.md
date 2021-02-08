```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 \
-subj "/C=US/ST=State/L=City/O=Org/OU=Org/CN=localhost" \
-addext "subjectAltName = DNS:localhost"
go run server.go
```
