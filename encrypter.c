#include <stdio.h>
#include <stdlib.h>
#include <tomcrypt.h>
#include <time.h>
#include <string.h>

int main(int argc, char *argv[]){
	
	char *buffer, *IV, *key;
	symmetric_CTR ctr;
	int err;
	
	key = argv[1];
	IV = argv[2];
	buffer = argv[3];

	//REGISTER
	if (register_cipher(&aes_desc) == -1){
		return -1;
	}

	if (( err = ctr_start(find_cipher("aes"), IV, key, 16, 0, CTR_COUNTER_LITTLE_ENDIAN, &ctr)) != CRYPT_OK){
		printf("setup() error: %s", error_to_string(err));
		return (-1);
	}
	
	if (( err = ctr_encrypt(buffer, buffer, strlen(buffer), &ctr)) != CRYPT_OK){
		printf("encrypt failed");
		return -1;
	}
	printf("%s", buffer);

	if (( err = ctr_done(&ctr)) != CRYPT_OK){
		printf("ctr_done failed");
		return -1;
	}
	
	zeromem(key, sizeof(key));
	zeromem(&ctr, sizeof(ctr));

	return 0;
}
