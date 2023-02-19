bin_PROGRAMS = oneway onewaytests
oneway_SOURCES = src/oneway.cpp src/main.cpp src/build-number.h
oneway_CPPFLAGS = -Iexternal -Wno-deprecated-declarations
oneway_LDADD = -Lexternal/cryptopp -lcryptopp
oneway_DEPENDENCIES = cryptopp

onewaytests_SOURCES = tests/main.cpp tests/unit-tests.cpp src/oneway.cpp src/build-number.h
onewaytests_CPPFLAGS = -Iexternal -Wno-deprecated-declarations -DTESTS ${GTEST_CFLAGS}
onewaytests_LDADD = -Lexternal/cryptopp -lcryptopp ${GTEST_LIBS}
onewaytests_DEPENDENCIES = cryptopp

TESTS = onewaytests tests/general-invoke.sh
BUILT_SOURCES = src/build-number.h cryptopp

src/build-number.h: src/.build-number
	@echo "// This is auto-gerenared file, do not modify" >src/build-number.h
	@echo "//" >>src/build-number.h
	@echo "" >>src/build-number.h
	@echo "constexpr int BUILD_NUMBER = $(shell cat src/.build-number);" >>src/build-number.h

.PHONY: cryptopp
cryptopp:
	cp --update external/cryptopp-pem/* external/cryptopp/
	$(MAKE) --directory external/cryptopp static
