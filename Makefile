
oneway: oneway.o cencode.o cdecode.o
	g++ -o oneway oneway.o cencode.o cdecode.o -lssl -lcrypto

oneway.o: oneway.cpp
	g++ -Wall -fexceptions -g -c -I libb64-1.2/include  oneway.cpp -o oneway.o

cencode.o: libb64-1.2/src/cencode.c
	gcc -Wall -pedantic -Ilibb64-1.2/include -c libb64-1.2/src/cencode.c -o cencode.o

cdecode.o: libb64-1.2/src/cdecode.c
	gcc -Wall -pedantic -Ilibb64-1.2/include -c libb64-1.2/src/cdecode.c -o cdecode.o
	
