bin_PROGRAMS = oneway onewaytests
oneway_SOURCES = src/oneway.cpp src/main.cpp src/build-number.h
oneway_CPPFLAGS = -Iexternal -Wno-deprecated-declarations
oneway_LDADD = -Lexternal/cryptopp -lcryptopp
oneway_DEPENDENCIES = cryptopp

lib_LTLIBRARIES = liboneway.la
liboneway_la_SOURCES = src/oneway.cpp src/build-number.h
liboneway_la_LIBADD = -Lexternal/cryptopp -lcryptopp
liboneway_la_CPPFLAGS = -Iexternal -Wno-deprecated-declarations
liboneway_la_LDFLAGS = -version-info 0:0:0
liboneway_la_DEPENDENCIES = cryptopp

onewaytests_SOURCES = tests/main.cpp tests/unit-tests.cpp src/oneway.cpp src/build-number.h
onewaytests_CPPFLAGS = -Og -Iexternal -Wno-deprecated-declarations -DTESTS ${GTEST_CFLAGS}
onewaytests_LDFLAGS = -ggdb
onewaytests_LDADD = -Lexternal/cryptopp -lcryptopp ${GTEST_LIBS} tests/vectors.o
onewaytests_DEPENDENCIES = cryptopp tests/vectors.o

TESTS = onewaytests tests/general-invoke.sh
BUILT_SOURCES = tests/vectors.o src/build-number.h cryptopp

tests/vectors.o: tests/test-vectors/*
	$(LD) -r -b binary -o tests/vectors.o tests/test-vectors/*

src/build-number.h: src/.build-number
	@echo "// This is auto-gerenared file, do not modify" >src/build-number.h
	@echo "//" >>src/build-number.h
	@echo "" >>src/build-number.h
	@echo "constexpr int BUILD_NUMBER = $(shell cat src/.build-number);" >>src/build-number.h

.PHONY: cryptopp
cryptopp:
	cp --update external/cryptopp-pem/* external/cryptopp/
	$(MAKE) --directory external/cryptopp static
