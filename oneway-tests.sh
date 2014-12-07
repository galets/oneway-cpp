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

dd if=/dev/urandom of=/tmp/source bs=100 count=$RANDOM

$PRG --genkey /tmp/private1.key || fail
$PRG --genkey > /tmp/private2.key || fail

$PRG --publickey /tmp/private1.key /tmp/public1.key || fail
$PRG --publickey < /tmp/private2.key > /tmp/public2.key || fail
$PRG --publickey /tmp/private2.key > /tmp/public2a.key || fail

$PRG --encrypt /tmp/public1.key /tmp/source /tmp/dest1 || fail
$PRG --encrypt /tmp/public2.key /tmp/source > /tmp/dest2 || fail
$PRG --encrypt /tmp/public2a.key < /tmp/source > /tmp/dest2a || fail

$PRG --decrypt /tmp/private1.key /tmp/dest1 /tmp/s1 || fail
$PRG --decrypt /tmp/private2.key < /tmp/dest2 > /tmp/s2 || fail
$PRG --decrypt /tmp/private2.key /tmp/dest2a > /tmp/s2a || fail

compare /tmp/source /tmp/s1 
compare /tmp/source /tmp/s2 
compare /tmp/source /tmp/s2a


