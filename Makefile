all: mytar.c
	cc -o mytar mytar.c -Wall -Wextra  -std=c99

clean: 
	rm mytar