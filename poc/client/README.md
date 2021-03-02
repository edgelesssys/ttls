## Build
```bash
mkdir build && cd build
cmake ..
make
```

Before running the client, copy the server's CA certificate in the build directory. Then execute the client:
```bash
cp ../../server/ca.crt .
./client
```
