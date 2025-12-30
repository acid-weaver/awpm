/**
 * \file            main.c
 * \brief           Entry point to TUI
 * \author          Acid Weaver
 * \date            2025-12-27
 * \details
 * Initializes the application, parses command-line arguments, and invokes
 * the appropriate modules based on user input.
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

#include <ncurses.h>
#include <panel.h>

int main(int argc, char* argv[]) {
    initscr();

    printw("Hello World!");

    WINDOW* win = newwin(20, 40, 2, 1);
    refresh();

    box(win, 0, 0);
    wprintw(win, "Window Test");
    wrefresh(win);
    getch();

    PANEL* pan = new_panel(win);
    mvwprintw(win, 1, 0, "Panel test");
    // wrefresh(win);
    update_panels();
    doupdate();

    getch();
    endwin();
    return 0;
}
