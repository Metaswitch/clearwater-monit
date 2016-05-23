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


#ifndef BOX_INCLUDED
#define BOX_INCLUDED


/**
 * Class for terminal table output.
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


typedef enum {
        BoxAlign_Left = 0,
        BoxAlign_Right
} __attribute__((__packed__)) BoxAlign_T;


typedef struct BoxColumn_T {
        const char *name;
        int width;
        boolean_t wrap;
        BoxAlign_T align;
} BoxColumn_T;


#define T Box_T
typedef struct T *T;


/**
 * Strip the UTF-8 table control characters in the string.
 * @param s The string to strip
 * @return A pointer to s
 */
char *Box_strip(char *s);


/**
 * Constructs a terminal table object.
 * @param b The output stringbuffer
 * @param columnsCount Count of table columns
 * @param columns Array of BoxColumn_T columns specification
 * @param printHeader true if the header should be printed otherwise false
 * @return A new terminal table object
 */
T Box_new(StringBuffer_T b, int columnsCount, BoxColumn_T *columns, boolean_t printHeader); //FIXME: when OutputStream is added, use it instead of StringBuffer


/**
 * Destroy a Box object and free allocated resources
 * @param t a Box object reference
 */
void Box_free(T *t);


/**
 * Print a table column
 * @param t The terminal table object
 * @param format A string with optional var args
 */
void Box_printColumn(T t, const char *format, ...) __attribute__((format (printf, 2, 3)));


#undef T
#endif

