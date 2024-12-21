#ifndef DATABASE_H
#define DATABASE_H

#include "utils.h"
#include <sqlite3.h>

int initialize_database(sqlite3** db, struct config cfg);
int user_exists(sqlite3* db, const char* username);

#endif // DATABASE_H

