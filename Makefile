all:
	gcc main.c -static -lcrypto -lssl -ldl -lz
