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

// libmonit
#include "util/Str.h"


/**
 * Implementation of the Terminal color interface
 *
 * @author http://www.tildeslash.com/
 * @see http://www.mmonit.com/
 * @file
 */


/* -------------------------------------------------------- Public Methods */


boolean_t TermColor_support() {
        if (! (Run.flags & Run_NoColor)) {
                if (getenv("COLORTERM")) {
                        return true;
                } else {
                        char *term = getenv("TERM");
                        if (term && (Str_startsWith(term, "screen") || Str_startsWith(term, "xterm") || Str_startsWith(term, "vt100") || Str_startsWith(term, "ansi") || Str_startsWith(term, "linux") || Str_sub(term, "color")))
                                return true;
                }
        }
        return false;
}


boolean_t TermColor_has(char *s) {
        return STR_DEF(s) ? (boolean_t)Str_sub(s, "\033[") : false;
}


char *TermColor_strip(char *s) {
        if (STR_DEF(s)) {
                int x, y;
                boolean_t ansi = false;
                for (x = 0, y = 0; s[y]; y++) {
                        if (s[y] == '\033' && s[y + 1] == '[') {
                                // Escape sequence start
                                ansi = true;
                                y++; // ++ to skip 'ESC['
                        } else if (ansi) {
                                // Escape sequence stop
                                if (s[y] >= 64 && s[y] <= 126)
                                        ansi = false;
                        } else {
                                s[x++] = s[y];
                        }
                }
                s[x] = 0;
        }
        return s;
}

