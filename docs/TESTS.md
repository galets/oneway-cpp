# Testing notes

Two suites, both wired into CTest:

- `unit`: gtest binary `onewaytests` (`tests/main.cpp`,
  `tests/unit-tests.cpp`). Vectors from `tests/test-vectors/*`
  embedded via `ld -r -b binary` into `vectors.o`.
- `invoke`: `tests/general-invoke.sh` round-trip on built `oneway`
  binary. Uses `$PRG` (`PRG=${PRG:-./oneway}`); CTest sets
  `PRG=$<TARGET_FILE:oneway>`.

Run native build with tests:

```sh
cmake -S . -B build/native
cmake --build build/native
ctest --test-dir build/native --output-on-failure
```
