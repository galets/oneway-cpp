bin_PROGRAMS = oneway onewaytests
oneway_SOURCES = src/oneway.cpp src/main.cpp
oneway_CPPFLAGS = -Iexternal -Wno-deprecated-declarations
oneway_LDADD = -Lexternal/cryptopp -lcryptopp
oneway_DEPENDENCIES = cryptopp

onewaytests_SOURCES = tests/main.cpp tests/unit-tests.cpp src/oneway.cpp
onewaytests_CPPFLAGS = -Iexternal -Wno-deprecated-declarations -DTESTS ${GTEST_CFLAGS}
onewaytests_LDADD = -Lexternal/cryptopp -lcryptopp ${GTEST_LIBS}
onewaytests_DEPENDENCIES = cryptopp

TESTS = onewaytests tests/general-invoke.sh

.PHONY: cryptopp
cryptopp: external/cryptopp-pem/*.cpp external/cryptopp-pem/*.h external/cryptopp-pem/*
	cp --update external/cryptopp-pem/* external/cryptopp/
	$(MAKE) --directory external/cryptopp
