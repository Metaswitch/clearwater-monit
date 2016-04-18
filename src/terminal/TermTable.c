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


#include "config.h"

#include <stdlib.h>

#include "monit.h"
#include "TermColor.h"
#include "TermTable.h"

// libmonit
#include "util/Str.h"


/**
 * Implementation of the Terminal table interface using UTF-8 box:
 * http://www.unicode.org/charts/PDF/U2500.pdf
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* ------------------------------------------------------------ Definitions */


#define BOX_HORIZONTAL          "\u2500" // ─
#define BOX_HORIZONTAL_DOWN     "\u252c" // ┬
#define BOX_VERTICAL            "\u2502" // │
#define BOX_VERTICAL_HORIZONTAL "\u253c" // ┼
#define BOX_VERTICAL_RIGHT      "\u251c" // ├
#define BOX_VERTICAL_LEFT       "\u2524" // ┤
#define BOX_DOWN_RIGHT          "\u250c" // ┌
#define BOX_DOWN_LEFT           "\u2510" // ┐
#define BOX_UP_HORIZONTAL       "\u2534" // ┴
#define BOX_UP_RIGHT            "\u2514" // └
#define BOX_UP_LEFT             "\u2518" // ┘


#define T TermTable_T
struct T {
        struct {
                unsigned row;
                unsigned column;
        } index;
        struct {
                struct {
                        boolean_t disabled;
                        char *color;
                } header;
        } options;
        unsigned columnsCount;
        TermTableColumn_T *columns;
        StringBuffer_T b;
};


/* ------------------------------------------------------- Private Methods */


static void _printBorderTop(T t) {
        StringBuffer_append(t->b, BOX_DOWN_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_HORIZONTAL_DOWN BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_DOWN_LEFT "\n");
}


static void _printBorderMiddle(T t) {
        StringBuffer_append(t->b, BOX_VERTICAL_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_VERTICAL_HORIZONTAL BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_VERTICAL_LEFT "\n");
}


static void _printBorderBottom(T t) {
        StringBuffer_append(t->b, BOX_UP_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_UP_HORIZONTAL BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_UP_LEFT "\n");
}


static void _printHeader(T t) {
        for (int i = 0; i < t->columnsCount; i++) {
                StringBuffer_append(t->b, BOX_VERTICAL " ");
                StringBuffer_append(t->b, "%s%-*s%s", t->options.header.color, t->columns[i].width, t->columns[i].name, TERMCOLOR_DEFAULT);
                StringBuffer_append(t->b, " ");
        }
        StringBuffer_append(t->b, BOX_VERTICAL "\n");
        t->index.row++;
}


/* -------------------------------------------------------- Public Methods */


boolean_t TermTable_support() {
        if (! (Run.flags & Run_NoTable)) {
                char *locale = getenv("LC_CTYPE");
                if (locale && Str_sub(locale, "UTF-8"))
                        return true;
        }
        return false;
}


char *TermTable_strip(char *s) {
        if (STR_DEF(s)) {
                int x, y;
                boolean_t separator = false;
                for (x = 0, y = 0; s[y]; y++) {
                        if (! separator) {
                                if (s[y] == 0xE2 && s[y + 1] == 0x94) {
                                        if (s[y + 2] == 0x8c || s[y + 2] == 0x94 || s[y + 2] == 0x9c)
                                                separator = true; // Drop the whole separator line
                                        else if (s[y + 2] >= 0x80 && s[y + 2] <= 0xBF)
                                                y += 2; // to skip 3 characters of UTF-8 box drawing character
                                } else {
                                        s[x++] = s[y];
                                }
                        } else if (s[y] == '\n') {
                                separator = false;
                        }
                }
                s[x] = 0;
        }
        return s;
}


T TermTable_new(StringBuffer_T b, int columnsCount, TermTableColumn_T *columns, TermTableOptions_T options) {
        ASSERT(b);
        ASSERT(columns);
        ASSERT(columnsCount > 0);
        T t;
        NEW(t);
        t->b = b;
        t->columnsCount = columnsCount;
        t->columns = columns;
        // Default options
        t->options.header.color = TERMCOLOR_LIGHTCYAN; // Note: hardcoded, option setting can be implemented if needed
        // Options
        t->options.header.disabled = options.noHeader;
        return t;
}


void TermTable_free(T *t) {
        ASSERT(t && *t);
        _printBorderBottom(*t);
        FREE(*t);
}


void TermTable_printColumn(T t, const char *format, ...) {
        ASSERT(t);
        ASSERT(format);
        if (t->index.row == 0 && t->index.column == 0) {
                _printBorderTop(t);
                if (! t->options.header.disabled) {
                        _printHeader(t);
                        _printBorderMiddle(t);
                }
        } else if (t->index.column > t->columnsCount - 1) {
                t->index.column = 0;
                _printBorderMiddle(t);
        }
        StringBuffer_append(t->b, BOX_VERTICAL " ");
        va_list ap;
        va_start(ap, format);
        char *s = Str_vcat(format, ap);
        va_end(ap);
        if (TermColor_has(s)) {
                StringBuffer_append(t->b, "%-*s", (int)(t->columns[t->index.column].width + strlen(TERMCOLOR_RED) + strlen(TERMCOLOR_DEFAULT)), s);
        } else {
                Str_trunc(s, t->columns[t->index.column].width);
                StringBuffer_append(t->b, "%-*s", t->columns[t->index.column].width, s);
        }
        FREE(s);
        StringBuffer_append(t->b, " ");
        if (++t->index.column > t->columnsCount - 1) {
                StringBuffer_append(t->b, BOX_VERTICAL "\n");
                t->index.row++;
        }
}

