#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>


void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void handle_interrupt(int sig) {
    printf("\nExiting wpassman.\n");
    exit(0);
}

int std_input(const char *input_name, const char *description, char *result, size_t result_size) {
    if (!result || result_size == 0) {
        fprintf(stderr, "Invalid buffer provided for %s input.\n", input_name);
        return -1;
    }

    if (strlen(description) == 0) {
        printf("Enter %s: ", input_name);
    } else {
        printf("Enter %s %s: ", input_name, description);
    }

    if (fgets(result, result_size, stdin) == NULL) {
        fprintf(stderr, "Error reading %s.\n", input_name);
        return -1;
    }

    result[strcspn(result, "\n")] = '\0'; // Remove newline
    return 0;
}

int secure_input(const char *input_name, const char *description, char *result, size_t result_size) {
    int status_code = 0;
    struct termios oldt, newt;

    // Disable echo
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        fprintf(stderr, "Error getting terminal attributes.\n");
        return -1;
    }
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        fprintf(stderr, "Error disabling echo.\n");
        return -1;
    }

    // Read input
    status_code = std_input(input_name, description, result, result_size);

    // Restore terminal settings
    if (tcsetattr(STDIN_FILENO, TCSANOW, &oldt) != 0) {
        fprintf(stderr, "Error restoring terminal attributes.\n");
        return -1;
    }

    printf("\n");
    return status_code;
}

