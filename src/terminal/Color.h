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


#ifndef COLOR_INCLUDED
#define COLOR_INCLUDED


/**
 * Class for terminal color output.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


#define COLOR_RED     "\033[0;31m"
#define COLOR_GREEN   "\033[0;32m"
#define COLOR_YELLOW  "\033[0;33m"
#define COLOR_BLUE    "\033[0;34m"
#define COLOR_DEFAULT "\033[0m"

#define Color_red(format, ...)    COLOR_RED format COLOR_DEFAULT, ##__VA_ARGS__
#define Color_green(format, ...)  COLOR_GREEN format COLOR_DEFAULT, ##__VA_ARGS__
#define Color_yellow(format, ...) COLOR_YELLOW format COLOR_DEFAULT, ##__VA_ARGS__
#define Color_blue(format, ...)   COLOR_BLUE format COLOR_DEFAULT, ##__VA_ARGS__


/**
 * Test terminal color support
 * @return true if colors are supported, otherwise false
 */
boolean_t Color_support();


/**
 * Strip the ANSI color sequences in the string.
 * Example:
 * <pre>
 * char s[] = "\033[31mHello\033[0m";
 * Color_strip(s) -> Hello
 * </pre>
 * @param s The string to strip
 * @return A pointer to s
 */
char *Color_strip(char *s);


#endif

