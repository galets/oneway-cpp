
oneway: oneway.o
	g++ -o oneway oneway.o -lssl -lcrypto

oneway.o: oneway.cpp
	g++ -Wall -fexceptions -g -c -I libb64-1.2/include  oneway.cpp -o oneway.o

