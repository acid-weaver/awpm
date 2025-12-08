/**
 * \file            config.c
 * \brief           Main entry point for the application
 * \author          Your GitHub Name
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ini.h"

struct config cfg;

static int handler(void *user, const char *section, const char *name,
                   const char *value) {
    struct config *cfg = (struct config *)user;

    if (strcmp(name, "db_path") == 0) {
        strncpy(cfg->db_path, value, sizeof(cfg->db_path) - 1);
    } else if (strcmp(name, "debug") == 0) {
        cfg->debug = atoi(value);
    } else if (strcmp(name, "multiple_accs_per_source") == 0) {
        cfg->multiple_accs_per_source = atoi(value);
    } else {
        return 0; // unknown key
    }
    return 1;
}

int config_load(const char *path) {
    // Set defaults
    memset(&cfg, 0, sizeof(cfg));
    strncpy(cfg.db_path, "/var/local/awpm/awpm.db", sizeof(cfg.db_path) - 1);
    cfg.debug                    = 0;
    cfg.multiple_accs_per_source = 0;

    if (ini_parse(path, handler, &cfg) < 0) {
        fprintf(stderr, "Cannot load config file: %s\n", path);
        return -1;
    }

    return 0;
}
