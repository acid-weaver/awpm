/**
 * \file            clipboard.c
 * \brief           Clipboard integration utilities
 * \author          Acid Weaver
 * \date            2025-12-16
 * \details
 * This file provides functions for clipboard usage.
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

#define _GNU_SOURCE

#include "lib/clipboard.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int write_all(int fd, const void* buf, size_t len) {
    const unsigned char* p = (const unsigned char*)buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/**
 * Send bytes to Wayland clipboard via `wl-copy --foreground --paste-once`.
 * This call BLOCKS until the first paste happens (or wl-copy exits).
 *
 * Returns 0 on success, -1 on error.
 */
int wl_copy_paste_once_bytes(const void* data, size_t len) {
    if (!data || len == 0) {
        errno = EINVAL;
        return 1;
    }

    int pipefd[2];
#if defined(HAVE_PIPE2)
    if (pipe2(pipefd, O_CLOEXEC) != 0) return -1;
#else
    if (pipe(pipefd) != 0) return -1;
    fcntl(pipefd[0], F_SETFD, fcntl(pipefd[0], F_GETFD) | FD_CLOEXEC);
    fcntl(pipefd[1], F_SETFD, fcntl(pipefd[1], F_GETFD) | FD_CLOEXEC);
#endif

    pid_t pid = fork();
    if (pid < 0) {
        // fork failed
        close(pipefd[0]);
        close(pipefd[1]);
        printf("%s", "DEBUG\n");
        return -1;
    }

    if (pid == 0) {
        // --- child: stdin <- pipe, exec wl-copy ---
        // Make the read end be stdin
        if (dup2(pipefd[0], STDIN_FILENO) < 0) _exit(127);
        close(pipefd[0]);
        close(pipefd[1]);

        // Replace process image with wl-copy
        execlp("wl-copy", "wl-copy", "--foreground", "--paste-once",
               (char*)NULL);

        // If we get here, exec failed
        _exit(127);
    }

    // --- parent: write data to child's stdin ---
    close(pipefd[0]);

    int rc = write_all(pipefd[1], data, len);
    // We’re done providing data; close to send EOF
    close(pipefd[1]);
    if (rc != 0) {
        // Best effort: reap child
        int status;
        (void)waitpid(pid, &status, 0);
        return -1;
    }

    // Wait for wl-copy to finish (it will block until first paste happens)
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) return -1;

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) return 0;

    // Map common failure: 127 usually means wl-copy not found
    if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
        errno = ENOENT; // "wl-copy" not found in PATH
    } else {
        errno = EIO;
    }
    return -1;
}
