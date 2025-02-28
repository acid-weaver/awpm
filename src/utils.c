/**
 * \file            utils.c
 * \brief           Implementation of common utilities
 * \author          Acid Weaver
 * \date            2024-12-23
 * \details
 * Implements utilities functions declared in utils.h.
 */

/* Copyright (C) 2024  Acid Weaver <acid.weaver@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <termios.h>
#include <unistd.h>

void handle_errors(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

void handle_interrupt(int sig) {
    printf("\nExiting awpm.\n");
    exit(0);
}

void disable_debugging() {
    if (prctl(PR_SET_DUMPABLE, 0) != 0) {
        perror("Failed to disable core dumps");
    }

    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != 0) {
        perror("Failed to restrict ptrace");
    }
}

int std_input(const char *input_name, const char *description, char *result,
              size_t result_size) {
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

int secure_input(const char *input_name, const char *description, char *result,
                 size_t result_size) {
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
