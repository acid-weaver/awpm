#ifndef CLI_H
#define CLI_H

// CLI parameters
#define CLI_NEW_CREDENTIAL "-n"
#define CLI_GET_CREDENTIAL "-g"
#define CLI_SET_MASTER_PSWD "-m"

#define CLI_DEBUG_MODE "--debug"

struct sqlite3;

void handle_add_new_entry(struct sqlite3* db, const char* username);
void handle_retrieve_creddata(struct sqlite3* db, const char* username);
void handle_set_master_pswd(struct sqlite3* db, const char* username);

#endif // CLI_H

