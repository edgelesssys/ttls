# Transparent TLS
# Build
```sh
sudo apt install clang-tidy-10 libmbedtls-dev
mkdir build
cd build
cmake ..
make
ctest
```

# Tests
Prerequisites:
* start poc's server
* copy cert.pem into `build/`

```bash
cd build && ctest
```
