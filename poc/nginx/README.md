# TLLS in nginx

1. Compile the loader for the ttls library
```bash
mkdir -p lib/build/
cd lib/build/
cmake ..
make
```

1. Preload the library
```bash
$ LD_PRELOAD=./lib/libloader.so ./nginx_graphene_debug
```
