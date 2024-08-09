#!/bin/sh
mkdir build/
cd build/

curl -LO https://musl.cc/aarch64-linux-musl-cross.tgz
tar xf aarch64-linux-musl-cross.tgz
tc="${PWD}/aarch64-linux-musl-cross/bin/aarch64-linux-musl-"

export CC="${tc}gcc"
export CXX="${tc}g++"
export LD="${tc}ld"
export AR="${tc}gcc-ar"
export AS="${tc}as"
export NM="${tc}gcc-nm"
export STRIP="${tc}strip"
export RANLIB="${tc}gcc-ranlib"
export OBJCOPY="${tc}objcopy"
export OBJDUMP="${tc}objdump"
export OBJSIZE="${tc}size"
export READELF="${tc}readelf"
export ADDR2LINE="${tc}addr2line"

curl -LO https://github.com/wangyu-/udp2raw/archive/refs/tags/20230206.0.tar.gz
tar xf 20230206.0.tar.gz
cd udp2raw-20230206.0/

export CFLAGS="-D_FORTIFY_SOURCE=2 -g0 -s -w -pipe -O3 -fstack-protector-strong"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -Wl,--as-needed,--sort-common,-z,relro,-z,now,--gc-sections,-O3"

make OPT="$CXXFLAGS $LDFLAGS -static" fast cc_local=$CXX

$STRIP --strip-all udp2raw
mv udp2raw ../../

cd ../../
rm -rf build/
