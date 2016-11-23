#!/bin/sh

mkdir output

cp -f config.txt ./output/config.txt
cp -f autologin.txt ./output/autologin.txt

g++ -std=c++11 -c -o output/DrcomForJY.o DrcomForJY.cpp
g++ -std=c++11 -c -o output/EAPOL.o EAPOL.cpp
g++ -std=c++11 -c -o output/getip.o getip.cpp
g++ -std=c++11 -c -o output/getmac.o getmac.cpp
g++ -std=c++11 -c -o output/md5.o md5.cpp
g++ -std=c++11 -c -o output/main.o main.cpp

g++ -std=c++11 -g -o output/Drcom2.elf output/main.o output/DrcomForJY.o output/EAPOL.o output/getip.o output/getmac.o output/md5.o -lpcap

