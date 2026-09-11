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
