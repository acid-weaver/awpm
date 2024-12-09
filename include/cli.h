#ifndef CLI_H
#define CLI_H

// CLI parameters
#define CLI_NEW "-n"
#define CLI_GET "-g"
#define CLI_DEBUG "--debug"

struct sqlite3;

void handle_add_new_entry(struct sqlite3 *db, const char *username);
void handle_retrieve_creddata(struct sqlite3 *db, const char *username);

#endif // CLI_H

