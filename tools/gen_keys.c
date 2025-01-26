#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdint.h>

int main(int argc, char **args) {

	if (argc < 2) {
		printf("%s <key len>\n", args[0]);
		return 1;
	}

	int key_len = atoi(args[1]);

	srand(time(0));

	for (int i = 0; i < key_len; i++) {

		uint32_t key = rand();
		printf("0x%x, ", key);
	}
	puts("");
}
