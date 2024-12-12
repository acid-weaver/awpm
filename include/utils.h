#ifndef UTILS_H
#define UTILS_H

// General constants
#define INPUT_BUFF_SIZE 64
#define MIN_PASSWORD_LENGTH 10
#define MAX_PASSWORD_LENGTH 32

// OpenSSL constants
#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define ITERATIONS 10000

#define OPTIONAL_PROMPT "(optional, hit Enter to skip)"
#define PSWD_CONFIRMATION "(confirm previously entered value)"

// Error messages
#define ERR_USER_NOT_FOUND "User not found."
#define ERR_DECRYPTION_FAILED "Decryption failed."

extern int DEBUG;                   // Global DEBUG flag
                                    // Initializing in main.c

#include <stdlib.h>

void handle_errors(const char *msg);
void handle_interrupt(int sig);
int std_input(const char *input_name, const char *description,
			  char *result, size_t result_size);
int secure_input(const char *input_name, const char *description,
				 char *result, size_t result_size);


#endif // UTILS_H

