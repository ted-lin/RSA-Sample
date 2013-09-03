all:
	gcc main.c -static -lcrypto -lssl -ldl -lz
clean:
	rm -f a.out
