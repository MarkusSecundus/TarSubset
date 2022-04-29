all: src.c
	cc -o tar src.c -Wall -Wextra -std=c99

clean: 
	rm tar