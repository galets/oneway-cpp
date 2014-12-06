
oneway: oneway.o
	g++ -o oneway oneway.o -lssl -lcrypto   
 
oneway.o: oneway.cpp
	g++ -Wall -fexceptions -g -c oneway.cpp -o oneway.o
	
