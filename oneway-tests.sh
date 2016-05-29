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

for BS in `seq 1 17 105`
do

	dd if=/dev/urandom of=/tmp/source bs=$BS count=$RANDOM

	$PRG --genkey /tmp/private1.key || fail
	$PRG --genkey > /tmp/private2.key || fail

	$PRG --publickey /tmp/private1.key /tmp/public1.key || fail
	$PRG --publickey < /tmp/private2.key > /tmp/public2.key || fail
	$PRG --publickey /tmp/private2.key > /tmp/public2a.key || fail

	$PRG --encrypt /tmp/public1.key /tmp/source /tmp/dest1 || fail
	$PRG --encrypt /tmp/public2.key /tmp/source > /tmp/dest2 || fail
	$PRG --encrypt /tmp/public2a.key < /tmp/source > /tmp/dest2a || fail

	$PRG --decrypt /tmp/private1.key /tmp/dest1 /tmp/s1 || fail
	SYMKEY=$($PRG --dump-key /tmp/private1.key /tmp/dest1 || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY /tmp/dest1 /tmp/s1.sk || fail

	$PRG --decrypt /tmp/private2.key < /tmp/dest2 > /tmp/s2 || fail
	SYMKEY=$($PRG --dump-key /tmp/private2.key /tmp/dest2 || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY /tmp/dest2 /tmp/s2.sk || fail

	$PRG --decrypt /tmp/private2.key /tmp/dest2a > /tmp/s2a || fail
	SYMKEY=$($PRG --dump-key /tmp/private2.key /tmp/dest2a || fail)
	echo "Symmetric key used: $SYMKEY"
	$PRG --decrypt-with-symkey $SYMKEY /tmp/dest2a /tmp/s2a.sk || fail

	compare /tmp/source /tmp/s1 
	compare /tmp/source /tmp/s1.sk 
	compare /tmp/source /tmp/s2 
	compare /tmp/source /tmp/s2.sk
	compare /tmp/source /tmp/s2a
	compare /tmp/source /tmp/s2a.sk

done

rm /tmp/private1.key /tmp/private2.key /tmp/public1.key /tmp/public2.key /tmp/public2a.key \
   /tmp/source /tmp/s1 /tmp/s2 /tmp/s2a /tmp/dest1 /tmp/dest2 /tmp/dest2a /tmp/s1.sk /tmp/s2.sk /tmp/s2a.sk
