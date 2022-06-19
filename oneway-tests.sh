#!/bin/bash

function fail() {
	echo "Errors returned"
	exit 1;
}

function compare() {
	cmp $1 $2 || (
		hexdump -C $1 > $1.hex
		hexdump -C $2 > $2.hex
		diff $1.hex $2.hex
		echo "Errors returned"
		exit 1;
	)
}

PRG=./oneway
TMP=${TMP:-/tmp}

for BS in `seq 1 17 105`
do

	dd if=/dev/urandom of=$TMP/source bs=$BS count=$RANDOM

	$PRG --genkey $TMP/private1.key || fail
	$PRG --genkey > $TMP/private2.key || fail

	$PRG --publickey $TMP/private1.key $TMP/public1.key || fail
	$PRG --publickey < $TMP/private2.key > $TMP/public2.key || fail
	$PRG --publickey $TMP/private2.key > $TMP/public2a.key || fail

	$PRG --encrypt $TMP/public1.key $TMP/source $TMP/dest1 || fail
	$PRG --encrypt $TMP/public2.key $TMP/source > $TMP/dest2 || fail
	$PRG --encrypt $TMP/public2a.key < $TMP/source > $TMP/dest2a || fail

	$PRG --decrypt $TMP/private1.key $TMP/dest1 $TMP/s1 || fail
	SYMKEY=$($PRG --dump-key $TMP/private1.key $TMP/dest1 || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY $TMP/dest1 $TMP/s1.sk || fail

	$PRG --decrypt $TMP/private2.key < $TMP/dest2 > $TMP/s2 || fail
	SYMKEY=$($PRG --dump-key $TMP/private2.key $TMP/dest2 || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY $TMP/dest2 $TMP/s2.sk || fail

	$PRG --decrypt $TMP/private2.key $TMP/dest2a > $TMP/s2a || fail
	SYMKEY=$($PRG --dump-key $TMP/private2.key $TMP/dest2a || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY $TMP/dest2a $TMP/s2a.sk || fail

	compare $TMP/source $TMP/s1 
	compare $TMP/source $TMP/s1.sk 
	compare $TMP/source $TMP/s2 
	compare $TMP/source $TMP/s2.sk
	compare $TMP/source $TMP/s2a
	compare $TMP/source $TMP/s2a.sk

done

rm $TMP/private1.key $TMP/private2.key $TMP/public1.key $TMP/public2.key $TMP/public2a.key \
   $TMP/source $TMP/s1 $TMP/s2 $TMP/s2a $TMP/dest1 $TMP/dest2 $TMP/dest2a $TMP/s1.sk $TMP/s2.sk $TMP/s2a.sk
