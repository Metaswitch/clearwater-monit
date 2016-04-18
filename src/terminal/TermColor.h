/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 *
 * You must obey the GNU Affero General Public License in all respects
 * for all of the code used other than OpenSSL.  
 */


#ifndef TERMCOLOR_INCLUDED
#define TERMCOLOR_INCLUDED


/**
 * Class for terminal color output.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define TERMCOLOR_BLACK        "\033[0;30m"
#define TERMCOLOR_RED          "\033[0;31m"
#define TERMCOLOR_GREEN        "\033[0;32m"
#define TERMCOLOR_YELLOW       "\033[0;33m"
#define TERMCOLOR_BLUE         "\033[0;34m"
#define TERMCOLOR_MAGENTA      "\033[0;35m"
#define TERMCOLOR_CYAN         "\033[0;36m"
#define TERMCOLOR_WHITE        "\033[0;37m"

#define TERMCOLOR_LIGHTBLACK   "\033[1;30m"
#define TERMCOLOR_LIGHTRED     "\033[1;31m"
#define TERMCOLOR_LIGHTGREEN   "\033[1;32m"
#define TERMCOLOR_LIGHTYELLOW  "\033[1;33m"
#define TERMCOLOR_LIGHTBLUE    "\033[1;34m"
#define TERMCOLOR_LIGHTMAGENTA "\033[1;35m"
#define TERMCOLOR_LIGHTCYAN    "\033[1;36m"
#define TERMCOLOR_LIGHTWHITE   "\033[1;37m"

#define TERMCOLOR_DEFAULT     "\033[0m"

#define TermColor_black(format, ...)        TERMCOLOR_BLACK format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_red(format, ...)          TERMCOLOR_RED format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_green(format, ...)        TERMCOLOR_GREEN format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_yellow(format, ...)       TERMCOLOR_YELLOW format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_blue(format, ...)         TERMCOLOR_BLUE format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_magenta(format, ...)      TERMCOLOR_MAGENTA format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_cyan(format, ...)         TERMCOLOR_CYAN format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_white(format, ...)        TERMCOLOR_WHITE format TERMCOLOR_DEFAULT, ##__VA_ARGS__

#define TermColor_lightBlack(format, ...)   TERMCOLOR_LIGHTBLACK format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightRed(format, ...)     TERMCOLOR_LIGHTRED format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightGreen(format, ...)   TERMCOLOR_LIGHTGREEN format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightYellow(format, ...)  TERMCOLOR_LIGHTYELLOW format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightBlue(format, ...)    TERMCOLOR_LIGHTBLUE format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightMagenta(format, ...) TERMCOLOR_LIGHTMAGENTA format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightCyan(format, ...)    TERMCOLOR_LIGHTCYAN format TERMCOLOR_DEFAULT, ##__VA_ARGS__
#define TermColor_lightWhite(format, ...)   TERMCOLOR_LIGHTWHITE format TERMCOLOR_DEFAULT, ##__VA_ARGS__

/**
 * Test terminal color support
 * @return true if colors are supported, otherwise false
 */
boolean_t TermColor_support();


/**
 * Test if the string contains an ANSI color sequence.
 * @return true if color is present, otherwise false
 */
boolean_t TermColor_has(char *s);


/**
 * Strip the ANSI color sequences in the string.
 * Example:
 * <pre>
 * char s[] = "\033[31mHello\033[0m";
 * TermColor_strip(s) -> Hello
 * </pre>
 * @param s The string to strip
 * @return A pointer to s
 */
char *TermColor_strip(char *s);


#endif

