# Building the project

Build oneway is now using cmake. To use build as a build directory, following is a command:

```bash
cmake -S . -B build/native && cmake --build build/native
```

## Cross-compilation

### armv7l
To cross-compile for armv7l, use the following command:

```bash
sudo apt install -y gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf
cmake -S . -B build/armv7l -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=armv7l -DCMAKE_C_COMPILER=arm-linux-gnueabihf-gcc -DCMAKE_CXX_COMPILER=arm-linux-gnueabihf-g++ && cmake --build build/armv7l
```

### aarch64
To cross-compile for aarch64, use the following command:

```bash
sudo apt install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
cmake -S . -B build/aarch64 -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_C_COMPILER=aarch64-linux-gnu-gcc -DCMAKE_CXX_COMPILER=aarch64-linux-gnu-g++ && cmake --build build/aarch64
```

### windows x86_64
To cross-compile for 64-bit Windows, use the following command:

```bash
sudo apt install -y mingw-w64
cmake -S . -B build/windows -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_SYSTEM_PROCESSOR=x86_64 -DCMAKE_C_COMPILER=x86_64-w64-mingw32-gcc-posix -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++-posix -DCMAKE_CXX_FLAGS="-static -static-libgcc -static-libstdc++" -DCMAKE_C_FLAGS="-static -static-libgcc" -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++" && cmake --build build/windows
```

Note: use the `-posix` compiler variants. The default `-win32`
variants fail building Crypto++ (`__gthread_cond_t` errors).
Static flags avoid `libwinpthread-1.dll` / `libgcc_s_seh-1.dll` /
`libstdc++-6.dll` runtime dependencies.
