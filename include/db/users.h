#ifndef USERS_H
#define USERS_H

#include "utils.h"
#include <sqlite3.h>

typedef struct {
    int id;                  // Primary key
    char username[INPUT_BUFF_SIZE];
    unsigned char salt[SALT_SIZE];
} user_t;

const char *get_current_username();
int populate_user_from_row(sqlite3_stmt *stmt, user_t *user);
int add_user(sqlite3 *db, const char *username);
int get_user_id_by_username(sqlite3 *db, const char *username, int *user_id);
int get_salt_by_user_id(sqlite3 *db, const int user_id, unsigned char *salt);

#endif // USERS_H

