#include "utils.h"
#include "cli.h"
#include "db/database.h"
#include "db/users.h"
// #include "db/creddata.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sqlite3.h>

int DEBUG = 0;                  // Global DEBUG flag


int main(int argc, char *argv[]) {
    sqlite3 *db = NULL;
    const char *username = get_current_username();

    signal(SIGINT, handle_interrupt); // Handle Ctrl-C
    signal(SIGTERM, handle_interrupt); // Handle kill signals

    // Initialize debugging flag
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], CLI_DEBUG) == 0) {
            DEBUG = 1;
            printf("Debug mode enabled.\n");
        }
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: wpassman %s | %s [%s]\n",
                CLI_NEW, CLI_GET, CLI_DEBUG);
        return 1;
    }

    if (!username) {
        fprintf(stderr, "Error: Unable to determine username.\n");
        return 1;
    }

    printf("Current user %s.\n", username);

    if (sqlite3_open("users.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    initialize_database(&db);

    if (strcmp(argv[1], CLI_NEW) == 0) {
        handle_add_new_entry(db, username);
    } else if (strcmp(argv[1], CLI_GET) == 0) {
        handle_retrieve_creddata(db, username);
    } else {
        fprintf(stderr, "Unknown parameter: %s\n", argv[1]);
    }

    sqlite3_close(db);
    return 0;
}

