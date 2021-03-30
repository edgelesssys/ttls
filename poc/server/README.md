The required certificate chain and keys can be created as follows:
```bash
cp ../../data_files/{ca.crt,server.crt,server.key} .
cat server.crt ca.crt > certs.pem
```

Then run the server:
```bash
go run server.go
```
