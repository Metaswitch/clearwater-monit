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
#include "Color.h"
#include "Box.h"

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


#define T Box_T
struct T {
        struct {
                unsigned row;
                unsigned column;
        } index;
        struct {
                struct {
                        boolean_t enabled;
                        char *color;
                } header;
        } options;
        unsigned columnsCount;
        BoxColumn_T *columns;
        StringBuffer_T b;
};


/* ------------------------------------------------------- Private Methods */


static void _printBorderTop(T t) {
        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_DOWN_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_HORIZONTAL_DOWN BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_DOWN_LEFT COLOR_RESET "\n");
}


static void _printBorderMiddle(T t) {
        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_VERTICAL_HORIZONTAL BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_VERTICAL_LEFT COLOR_RESET "\n");
}


static void _printBorderBottom(T t) {
        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_UP_RIGHT BOX_HORIZONTAL);
        for (int i = 0; i < t->columnsCount; i++) {
                for (int j = 0; j < t->columns[i].width; j++)
                        StringBuffer_append(t->b, BOX_HORIZONTAL);
                if (i < t->columnsCount - 1)
                        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_UP_HORIZONTAL BOX_HORIZONTAL);
        }
        StringBuffer_append(t->b, BOX_HORIZONTAL BOX_UP_LEFT COLOR_RESET "\n");
}


static void _printHeader(T t) {
        for (int i = 0; i < t->columnsCount; i++) {
                StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET " ");
                StringBuffer_append(t->b, "%s%-*s%s", t->options.header.color, t->columns[i].width, t->columns[i].name, COLOR_RESET);
                StringBuffer_append(t->b, " ");
        }
        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET "\n");
        t->index.row++;
}


/* -------------------------------------------------------- Public Methods */


char *Box_strip(char *s) {
        if (STR_DEF(s)) {
                int x, y;
                unsigned char *_s = (unsigned char *)s;
                boolean_t separator = false;
                for (x = 0, y = 0; s[y]; y++) {
                        if (! separator) {
                                if (_s[y] == 0xE2 && _s[y + 1] == 0x94) {
                                        if (_s[y + 2] == 0x8c || _s[y + 2] == 0x94 || _s[y + 2] == 0x9c)
                                                separator = true; // Drop the whole separator line
                                        else if (_s[y + 2] >= 0x80 && _s[y + 2] <= 0xBF)
                                                y += 2; // to skip 3 characters of UTF-8 box drawing character
                                } else {
                                        _s[x++] = _s[y];
                                }
                        } else if (_s[y] == '\n') {
                                separator = false;
                        }
                }
                _s[x] = 0;
        }
        return s;
}


T Box_new(StringBuffer_T b, int columnsCount, BoxColumn_T *columns, boolean_t printHeader) {
        ASSERT(b);
        ASSERT(columns);
        ASSERT(columnsCount > 0);
        T t;
        NEW(t);
        t->b = b;
        t->columnsCount = columnsCount;
        t->columns = columns;
        // Default options
        t->options.header.color = COLOR_BOLDCYAN; // Note: hardcoded, option setting can be implemented if needed
        // Options
        t->options.header.enabled = printHeader;
        return t;
}


void Box_free(T *t) {
        ASSERT(t && *t);
        if ((*t)->index.row > 0)
                _printBorderBottom(*t);
        FREE(*t);
}


void Box_printColumn(T t, const char *format, ...) {
        ASSERT(t);
        ASSERT(format);
        if (t->index.row == 0 && t->index.column == 0) {
                _printBorderTop(t);
                if (t->options.header.enabled) {
                        _printHeader(t);
                        _printBorderMiddle(t);
                }
        } else if (t->index.column > t->columnsCount - 1) {
                t->index.column = 0;
                _printBorderMiddle(t);
        }
        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET " ");
        va_list ap;
        va_start(ap, format);
        char *s = Str_vcat(format, ap);
        va_end(ap);
        int colorLengthOriginal = Color_length(s);
        if (strlen(s) - colorLengthOriginal > t->columns[t->index.column].width) {
                if (t->columns[t->index.column].wrap) {
                        //Note: The content wrap is currently supported only in the last column - adding wrap support for any column will require caching all columns before we can print a full line
                        ASSERT(t->index.column + 1 == t->columnsCount);
                        int i;
                        char color[STRLEN] = {};
                        if (colorLengthOriginal) {
                                // Cache the color code
                                boolean_t ansi = false;
                                for (int i = 0, j = 0; s[i]; i++) {
                                        if (s[i] == '\033' && s[i + 1] == '[') {
                                                // Escape sequence start
                                                color[j++] = '\033';
                                                color[j++] = '[';
                                                i++;
                                                ansi = true;
                                        } else if (ansi) {
                                                color[j++] = s[i];
                                                // Escape sequence stop
                                                if (s[i] >= 64 && s[i] <= 126)
                                                        break;
                                        }
                                }
                                // Strip the escape sequences, so we can break the line
                                Color_strip(s);
                        }
                        for (i = 0; s[i]; i++) {
                                if (i && i % t->columns[t->index.column].width == 0) {
                                        // Terminate current line
                                        if (*color)
                                                StringBuffer_append(t->b, COLOR_RESET);
                                        StringBuffer_append(t->b, " " COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET "\n");
                                        // Seek to the same column position
                                        for (int j = 0; j < t->index.column; j++) {
                                                StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET " ");
                                                StringBuffer_append(t->b, "%-*s", t->columns[j].width, " ");
                                                StringBuffer_append(t->b, " ");
                                        }
                                        // Separator
                                        StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET " ");
                                }
                                if (*color && i % t->columns[t->index.column].width == 0)
                                        StringBuffer_append(t->b, "%s", color);
                                StringBuffer_append(t->b, "%c", s[i]);
                        }
                        // Last line padding
                        int padding = t->columns[t->index.column].width - i % t->columns[t->index.column].width;
                        if (padding > 0 && padding < t->columns[t->index.column].width)
                                StringBuffer_append(t->b, "%-*s", padding, " ");
                        if (*color)
                                StringBuffer_append(t->b, COLOR_RESET);
                } else {
                        Str_trunc(s, t->columns[t->index.column].width);
                        int colorLengthCurrent = Color_length(s);
                        StringBuffer_append(t->b, "%-*s", t->columns[t->index.column].width + colorLengthCurrent, s);
                        if (colorLengthCurrent < colorLengthOriginal)
                                StringBuffer_append(t->b, COLOR_RESET);
                }
        } else {
                StringBuffer_append(t->b, t->columns[t->index.column].align == BoxAlign_Right ? "%*s" : "%-*s", t->columns[t->index.column].width + colorLengthOriginal, s);
        }
        FREE(s);
        StringBuffer_append(t->b, " ");
        if (++t->index.column > t->columnsCount - 1) {
                StringBuffer_append(t->b, COLOR_DARKGRAY BOX_VERTICAL COLOR_RESET "\n");
                t->index.row++;
        }
}

