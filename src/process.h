/*
 * Copyright (C) Tildeslash Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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

#ifndef MONIT_PROCESS_H
#define MONIT_PROCESS_H

#include "config.h"

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


/**
 * Update the process infomation.
 * @param s A Service object
 * @param pt Process tree
 * @param treesize Process tree size
 * @param pid Process PID to update
 * @return true if succeeded otherwise false.
 */
boolean_t Process_update(Service_T s, ProcessTree_T *pt, int treesize, pid_t pid);


/**
 * Initialize the process tree
 * @param pt_r Process tree reference
 * @param size_r Process tree size reference
 * @param pflags  Flags
 * @return The process tree size or -1 if failed
 */
int Process_initTree(ProcessTree_T **pt_r, int *size_r, ProcessEngine_Flags pflags);


/**
 * Delete the process tree
 * @param reference Process tree reference
 * @param size Process tree size reference
 */
void Process_deleteTree(ProcessTree_T **reference, int *size);


/**
 * Get process uptime
 * @param pid Process PID
 * @param pt Process tree reference
 * @param treesize Process tree size
 * @return The PID of the running running process or 0 if the process is not running.
 */
time_t Process_getUptime(pid_t pid, ProcessTree_T *pt, int treesize);


/**
 * Check if the process is running
 * @param s The service being checked
 * @return The PID of the running running process or 0 if the process is not running.
 */
int Process_running(Service_T s);


/**
 * Print a table with all processes matching a given pattern
 * @param pattern The process pattern
 */
void Process_testMatch(char *pattern);


/**
 * Initialize the system information
 * @return true if succeeded otherwise false.
 */
boolean_t init_system_info(void);


/**
 * Update system statistic
 * @return true if successful, otherwise false
 */
boolean_t update_system_info();


#endif

