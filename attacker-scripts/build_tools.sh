#!/bin/bash

#----------- dot11decrypt build -----------#
cd wpa2/
rm -rf build_dot11decrypt && mkdir build_dot11decrypt
cd build_dot11decrypt

cmake ../dot11decrypt
make -j$(nproc)

if [ -f "dot11decrypt" ]; then
    mv dot11decrypt ../d11decrypt
    echo "Success: binary moved to wpa2/d11decrypt"
else
    echo "Error: Build failed, binary not found."
fi

cd ../../
#----------- dot11decrypt build -----------#