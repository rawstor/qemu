# Qemu with rawstor support

# TL;DR

```
export PKG_CONFIG_PATH=${HOME}/local/lib/pkgconfig
mkdir build
cd build
../configure \
    --extra-cflags="$(pkg-config --cflags rawstor)" \
    --extra-ldflags="$(pkg-config --libs rawstor)"
make
```
