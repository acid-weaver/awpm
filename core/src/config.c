/**
 * \file            config.c
 * \brief           Main entry point for the application
 * \author          Acid Weaver
 * \date            2025-06-20
 * \details
 * Implements configuration functionality to use it across project needs.
 */

/* Copyright (C) 2024-2025  Acid Weaver <acid.weaver@gmail.com>
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

#include "core/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "lib/ini.h"

struct config cfg;

char* config_to_string() {
    static const char empty_string[] = "";
    char* result                     = NULL;
    size_t result_size               = 0;

    result_size =
        snprintf(NULL, 0,
                 "db_path: %s\nmultiple_accs_per_source: %i\ncfg.debug: "
                 "%i\nlogin_output: %s\nemail_output: %s\npswd_output: %s\n",
                 cfg.db_path, cfg.multiple_accs_per_source, cfg.debug,
                 cfg.login_output, cfg.email_output, cfg.pswd_output)
        + 1;
    result = malloc(result_size);

    if (result == NULL) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return (char*)empty_string;
    }

    snprintf(result, result_size,
             "db_path: %s\nmultiple_accs_per_source: %i\ncfg.debug: "
             "%i\nlogin_output: %s\nemail_output: %s\npswd_output: %s\n",
             cfg.db_path, cfg.multiple_accs_per_source, cfg.debug,
             cfg.login_output, cfg.email_output, cfg.pswd_output);

    return result;
}

static int handler(void* user, const char* section, const char* name,
                   const char* value) {
    struct config* cfg = (struct config*)user;

    // TODO VALIDATION

    if (strcmp(section, "general") == 0) {
        if (strcmp(name, "db_path") == 0) {
            strncpy(cfg->db_path, value, sizeof(cfg->db_path) - 1);

        } else if (strcmp(name, "debug") == 0) {
            cfg->debug = atoi(value);

        } else if (strcmp(name, "multiple_accs_per_source") == 0) {
            cfg->multiple_accs_per_source = atoi(value);

        } else {
            fprintf(stderr,
                    "Unknown parameter in config, section [%s] : %s = %s\n",
                    section, name, value);
            return 0; // unknown key
        }

    } else if (strcmp(section, "cli") == 0) {
        if (strcmp(name, "login_output") == 0) {
            strncpy(cfg->login_output, value, sizeof(cfg->login_output) - 1);

        } else if (strcmp(name, "email_output") == 0) {
            strncpy(cfg->email_output, value, sizeof(cfg->email_output) - 1);

        } else if (strcmp(name, "pswd_output") == 0) {
            strncpy(cfg->pswd_output, value, sizeof(cfg->pswd_output) - 1);

        } else {
            fprintf(stderr,
                    "Unknown parameter in config, section [%s] : %s = %s\n",
                    section, name, value);
            return 0;
        }
    }
    return 1;
}

int config_load(const char* path) {
    // Set defaults
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.db_path, "/var/local/awpm/awpm.db", sizeof(cfg.db_path) - 1);
    cfg.debug                    = 0;
    cfg.multiple_accs_per_source = 0;

    strncpy(cfg.login_output, "display", sizeof(cfg.login_output) - 1);
    strncpy(cfg.email_output, "display", sizeof(cfg.email_output) - 1);
    strncpy(cfg.pswd_output, "clipboard", sizeof(cfg.pswd_output) - 1);

    if (ini_parse(path, handler, &cfg) < 0) {
        fprintf(stderr, "Cannot load config file: %s\n", path);
        return -1;
    }

    return 0;
}
