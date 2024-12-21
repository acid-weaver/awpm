#ifndef UTILS_H
#define UTILS_H

// Input constants
#define INPUT_BUFF_SIZE 64

#define OPTIONAL_PROMPT "(optional, hit Enter to skip)"
#define PSWD_CONFIRMATION "(confirm previously entered value)"

// OpenSSL constants
#define SALT_SIZE 16
#define KEY_SIZE 32
#define IV_SIZE 16
#define ITERATIONS 10000

// Error messages
#define ERR_USER_NOT_FOUND "User not found."
#define ERR_DECRYPTION_FAILED "Decryption failed."

struct config {
    char db_path[INPUT_BUFF_SIZE * 4];
    int debug;
    int multiple_accs_per_source;
};

#include <stdlib.h>

void handle_errors(const char* msg);
void handle_interrupt(int sig);
int std_input(const char* input_name, const char* description,
              char* result, size_t result_size);
int secure_input(const char* input_name, const char* description,
                 char* result, size_t result_size);

#endif // UTILS_H

