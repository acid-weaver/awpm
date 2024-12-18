#include "utils.h"
#include "cli.h"
#include "db/database.h"
#include "db/users.h"
// #include "db/creddata.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sqlite3.h>
#include <openssl/crypto.h>

int DEBUG = 0;                  // Global DEBUG flag


int main(int argc, char* argv[]) {
    user_t user = {0};
    sqlite3* db = NULL;

    signal(SIGINT, handle_interrupt); // Handle Ctrl-C
    signal(SIGTERM, handle_interrupt); // Handle kill signals

    // Initialize debugging flag
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], CLI_DEBUG_MODE) == 0) {
            DEBUG = 1;
            printf("Debug mode enabled.\n");
        }
    }

    if (argc < 2) {
        fprintf(stderr, "Usage: pm %s | %s | %s [%s]\n",
                CLI_NEW_CREDENTIAL, CLI_GET_CREDENTIAL,
                CLI_SET_MASTER_PSWD, CLI_DEBUG_MODE);
        return 1;
    }

    user = user_init();
    if (strlen(user.username) == 0) {
        handle_errors("Unauthorized access impossible.\n");
        return 1;
    }

    printf("Greetings, %s!\n", user.username);

    if (sqlite3_open("awpm.db", &db) != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    initialize_database(&db);

    if (strcmp(argv[1], CLI_NEW_CREDENTIAL) == 0) {
        handle_add_new_entry(db, &user);
    } else if (strcmp(argv[1], CLI_GET_CREDENTIAL) == 0) {
        handle_retrieve_creddata(db, &user);
    } else if (strcmp(argv[1], CLI_SET_MASTER_PSWD) == 0) {
        handle_set_master_pswd(db, &user);
    } else {
        fprintf(stderr, "Unknown parameter: %s\n", argv[1]);
    }

    sqlite3_close(db);
    return 0;
}

