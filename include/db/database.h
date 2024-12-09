#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

int initialize_database(sqlite3 **db);
int user_exists(sqlite3 *db, const char *username);

#endif // DATABASE_H

