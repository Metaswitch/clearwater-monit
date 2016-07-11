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

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#ifdef HAVE_TIME_H
#include <time.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "monit.h"
#include "event.h"
#include "ProcessTree.h"
#include "process_sysdep.h"
#include "Box.h"
#include "Color.h"

// libmonit
#include "system/Time.h"


/**
 *  General purpose /proc methods.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


static int ptreesize = 0;
static ProcessTree_T *ptree = NULL;


/* ----------------------------------------------------------------- Private */


static void _delete(ProcessTree_T **pt, int *size) {
        ASSERT(pt);
        ProcessTree_T *_pt = *pt;
        if (_pt) {
                for (int i = 0; i < *size; i++) {
                        FREE(_pt[i].cmdline);
                        FREE(_pt[i].children.list);
                }
                FREE(_pt);
                *pt = NULL;
                *size = 0;
        }
}


/**
 * Search a leaf in the processtree
 * @param pid  pid of the process
 * @param pt  processtree
 * @param treesize  size of the processtree
 * @return process index if succeeded otherwise -1
 */
static int _findProcess(int pid, ProcessTree_T *pt, int size) {
        if (size > 0) {
                for (int i = 0; i < size; i++)
                        if (pid == pt[i].pid)
                                return i;
        }
        return -1;
}


/**
 * Fill data in the process tree by recusively walking through it
 * @param pt process tree
 * @param i process index
 */
static void _fillProcessTree(ProcessTree_T *pt, int index) {
        if (! pt[index].visited) {
                pt[index].visited            = true;
                pt[index].children.total     = pt[index].children.count;
                pt[index].memory.usage_total = pt[index].memory.usage;
                pt[index].cpu.usage_total    = pt[index].cpu.usage;
                for (int i = 0; i < pt[index].children.count; i++)
                        _fillProcessTree(pt, pt[index].children.list[i]);
                if (pt[index].parent != -1 && pt[index].parent != index) {
                        ProcessTree_T *parent_pt       = &pt[pt[index].parent];
                        parent_pt->children.total     += pt[index].children.total;
                        parent_pt->memory.usage_total += pt[index].memory.usage_total;
                        parent_pt->cpu.usage_total    += pt[index].cpu.usage_total;
                }
        }
}


/**
 * Adjust the CPU usage based on the available system resources: number of CPU cores the application may utilize. Single threaded application may utilized only one CPU core, 4 threaded application 4 cores, etc.. If the application
 * has more threads then the machine has cores, it is limited by number of cores, not threads.
 * @param now Current process informations
 * @param prev Process informations from previous cycle
 * @param delta The delta of system time between current and previous cycle
 * @return Process' CPU usage [%] since last cycle
 */
static float _cpuUsage(ProcessTree_T *now, ProcessTree_T *prev, double delta) {
        if (systeminfo.cpus > 0 && delta > 0 && prev->cpu.time > 0 && now->cpu.time > prev->cpu.time) {
                int divisor;
                if (now->threads > 1) {
                        if (now->threads >= systeminfo.cpus) {
                                // Multithreaded application with more threads then CPU cores
                                divisor = systeminfo.cpus;
                        } else {
                                // Multithreaded application with less threads then CPU cores
                                divisor = now->threads;
                        }
                } else {
                        // Single threaded application
                        divisor = 1;
                }
                float usage = (100. * (now->cpu.time - prev->cpu.time) / delta) / divisor;
                return usage > 100. ? 100. : usage;
        }
        return 0.;
}


static int _match(regex_t *regex) {
        int found = -1;
        // Scan the whole process tree and find the oldest matching process whose parent doesn't match the pattern
        for (int i = 0; i < ptreesize; i++)
                if (ptree[i].cmdline && regexec(regex, ptree[i].cmdline, 0, NULL, 0) == 0 && (i == ptree[i].parent || ! ptree[ptree[i].parent].cmdline || regexec(regex, ptree[ptree[i].parent].cmdline, 0, NULL, 0) != 0) && (found == -1 || ptree[found].uptime < ptree[i].uptime))
                        found = i;
        return found >= 0 ? ptree[found].pid : -1;
}


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the process tree
 * @return treesize >= 0 if succeeded otherwise < 0
 */
int ProcessTree_init(ProcessEngine_Flags pflags) {
        ProcessTree_T *oldptree = ptree;
        int oldptreesize = ptreesize;
        if (oldptree) {
                ptree = NULL;
                ptreesize = 0;
                // We need only process' cpu.time from the old ptree, so free dynamically allocated parts which we don't need before initializing new ptree (so the memory can be reused, otherwise the memory footprint will hold two ptrees)
                for (int i = 0; i < oldptreesize; i++) {
                        FREE(oldptree[i].cmdline);
                        FREE(oldptree[i].children.list);
                }
        }

        systeminfo.time_prev = systeminfo.time;
        systeminfo.time = Time_milli() / 100.;
        if ((ptreesize = initprocesstree_sysdep(&ptree, pflags)) <= 0 || ! ptree) {
                DEBUG("System statistic -- cannot initialize the process tree -- process resource monitoring disabled\n");
                Run.flags &= ~Run_ProcessEngineEnabled;
                if (oldptree)
                        _delete(&oldptree, &oldptreesize);
                return -1;
        } else if (! (Run.flags & Run_ProcessEngineEnabled)) {
                DEBUG("System statistic -- initialization of the process tree succeeded -- process resource monitoring enabled\n");
                Run.flags |= Run_ProcessEngineEnabled;
        }

        int root = -1; // Main process. Not all systems have main process with PID 1 (such as Solaris zones and FreeBSD jails), so we try to find process which is parent of itself
        ProcessTree_T *pt = ptree;
        double time_delta = systeminfo.time - systeminfo.time_prev;
        for (int i = 0; i < (volatile int)ptreesize; i ++) {
                if (oldptree) {
                        int oldentry = _findProcess(pt[i].pid, oldptree, oldptreesize);
                        if (oldentry != -1)
                                pt[i].cpu.usage = _cpuUsage(&pt[i], &oldptree[oldentry], time_delta);
                }
                // Note: on DragonFly, main process is swapper with pid 0 and ppid -1, so take also this case into consideration
                if ((pt[i].pid == pt[i].ppid) || (pt[i].ppid == -1)) {
                        root = pt[i].parent = i;
                } else {
                        // Find this process' parent
                        int parent = _findProcess(pt[i].ppid, pt, ptreesize);
                        if (parent == -1) {
                                /* Parent process wasn't found - on Linux this is normal: main process with PID 0 is not listed, similarly in FreeBSD jail.
                                 * We create virtual process entry for missing parent so we can have full tree-like structure with root. */
                                parent = ptreesize++;
                                pt = RESIZE(ptree, ptreesize * sizeof(ProcessTree_T));
                                memset(&pt[parent], 0, sizeof(ProcessTree_T));
                                root = pt[parent].ppid = pt[parent].pid = pt[i].ppid;
                        }
                        pt[i].parent = parent;
                        // Connect the child (this process) to the parent
                        RESIZE(pt[parent].children.list, sizeof(int) * (pt[parent].children.count + 1));
                        pt[parent].children.list[pt[parent].children.count] = i;
                        pt[parent].children.count++;
                }
        }
        FREE(oldptree); // Free the rest of old ptree
        if (root == -1) {
                DEBUG("System statistic error -- cannot find root process id\n");
                _delete(&ptree, &ptreesize);
                return -1;
        }

        _fillProcessTree(pt, root);

        return ptreesize;
}


/**
 * Delete the process tree
 */
void ProcessTree_delete() {
        _delete(&ptree, &ptreesize);
}


boolean_t ProcessTree_updateProcess(Service_T s, pid_t pid) {
        ASSERT(s);

        /* save the previous pid and set actual one */
        s->inf->priv.process._pid = s->inf->priv.process.pid;
        s->inf->priv.process.pid  = pid;

        int leaf = _findProcess(pid, ptree, ptreesize);
        if (leaf != -1) {
                /* save the previous ppid and set actual one */
                s->inf->priv.process._ppid             = s->inf->priv.process.ppid;
                s->inf->priv.process.ppid              = ptree[leaf].ppid;
                s->inf->priv.process.uid               = ptree[leaf].cred.uid;
                s->inf->priv.process.euid              = ptree[leaf].cred.euid;
                s->inf->priv.process.gid               = ptree[leaf].cred.gid;
                s->inf->priv.process.uptime            = ptree[leaf].uptime;
                s->inf->priv.process.threads           = ptree[leaf].threads;
                s->inf->priv.process.children          = ptree[leaf].children.total;
                s->inf->priv.process.zombie            = ptree[leaf].zombie;
                s->inf->priv.process.cpu_percent       = ptree[leaf].cpu.usage;
                s->inf->priv.process.total_cpu_percent = ptree[leaf].cpu.usage_total > 100. ? 100. : ptree[leaf].cpu.usage_total;
                s->inf->priv.process.mem               = ptree[leaf].memory.usage;
                s->inf->priv.process.total_mem         = ptree[leaf].memory.usage_total;
                if (systeminfo.mem_max > 0) {
                        s->inf->priv.process.total_mem_percent = ptree[leaf].memory.usage_total >= systeminfo.mem_max ? 100. : (100. * (double)ptree[leaf].memory.usage_total / (double)systeminfo.mem_max);
                        s->inf->priv.process.mem_percent       = ptree[leaf].memory.usage >= systeminfo.mem_max ? 100. : (100. * (double)ptree[leaf].memory.usage / (double)systeminfo.mem_max);
                }
                return true;
        }
        Util_resetInfo(s);
        return false;
}


time_t ProcessTree_getProcessUptime(pid_t pid) {
        if (ptree) {
                int leaf = _findProcess(pid, ptree, ptreesize);
                return (time_t)((leaf >= 0 && leaf < ptreesize) ? ptree[leaf].uptime : -1);
        }
        return 0;
}


pid_t ProcessTree_findProcess(Service_T s) {
        ASSERT(s);
        // Test the cached PID first
        if (s->inf->priv.process.pid > 0) {
                errno = 0;
                if (getpgid(s->inf->priv.process.pid) > -1 || errno == EPERM)
                        return s->inf->priv.process.pid;
        }
        // If the cached PID is not running, scan for the process again
        if (s->matchlist) {
                // Update the process tree including command line
                ProcessTree_init(ProcessEngine_CollectCommandLine);
                if (Run.flags & Run_ProcessEngineEnabled) {
                        int pid = _match(s->matchlist->regex_comp);
                        if (pid >= 0)
                                return pid;
                } else {
                        DEBUG("Process information not available -- skipping service %s process existence check for this cycle\n", s->name);
                        // Return value is NOOP - it is based on existing errors bitmap so we don't generate false recovery/failures
                        return ! (s->error & Event_Nonexist);
                }
        } else {
                pid_t pid = Util_getPid(s->path);
                if (pid > 0) {
                        errno = 0;
                        if (getpgid(pid) > -1 || errno == EPERM)
                                return pid;
                        DEBUG("'%s' process test failed [pid=%d] -- %s\n", s->name, pid, STRERROR);
                }
        }
        Util_resetInfo(s);
        return 0;
}


void ProcessTree_testMatch(char *pattern) {
        regex_t *regex_comp;
        int reg_return;

        NEW(regex_comp);
        if ((reg_return = regcomp(regex_comp, pattern, REG_NOSUB|REG_EXTENDED))) {
                char errbuf[STRLEN];
                regerror(reg_return, regex_comp, errbuf, STRLEN);
                regfree(regex_comp);
                FREE(regex_comp);
                printf("Regex %s parsing error: %s\n", pattern, errbuf);
                exit(1);
        }
        ProcessTree_init(ProcessEngine_CollectCommandLine);
        if (Run.flags & Run_ProcessEngineEnabled) {
                int count = 0;
                printf("List of processes matching pattern \"%s\":\n", pattern);
                StringBuffer_T output = StringBuffer_create(256);
                Box_T t = Box_new(output, 4, (BoxColumn_T []){
                                {.name = "",        .width = 1,  .wrap = false, .align = BoxAlign_Left},
                                {.name = "PID",     .width = 5,  .wrap = false, .align = BoxAlign_Right},
                                {.name = "PPID",    .width = 5,  .wrap = false, .align = BoxAlign_Right},
                                {.name = "Command", .width = 56, .wrap = true,  .align = BoxAlign_Left}
                          }, true);
                // Select the process matching the pattern
                int pid = _match(regex_comp);
                // Print all matching processes and highlight the one which is selected
                for (int i = 0; i < ptreesize; i++) {
                        if (ptree[i].cmdline && ! strstr(ptree[i].cmdline, "procmatch")) {
                                if (! regexec(regex_comp, ptree[i].cmdline, 0, NULL, 0)) {
                                        if (pid == ptree[i].pid) {
                                                Box_setColumn(t, 1, COLOR_BOLD "*" COLOR_RESET);
                                                Box_setColumn(t, 2, COLOR_BOLD "%d" COLOR_RESET, ptree[i].pid);
                                                Box_setColumn(t, 3, COLOR_BOLD "%d" COLOR_RESET, ptree[i].ppid);
                                                Box_setColumn(t, 4, COLOR_BOLD "%s" COLOR_RESET, ptree[i].cmdline);
                                        } else {
                                                Box_setColumn(t, 2, "%d", ptree[i].pid);
                                                Box_setColumn(t, 3, "%d", ptree[i].ppid);
                                                Box_setColumn(t, 4, "%s", ptree[i].cmdline);
                                        }
                                        Box_printRow(t);
                                        count++;
                                }
                        }
                }
                Box_free(&t);
                if (Run.flags & Run_Batch || ! Color_support())
                        Color_strip(Box_strip((char *)StringBuffer_toString(output)));
                printf("%s", StringBuffer_toString(output));
                StringBuffer_free(&output);
                printf("Total matches: %d\n", count);
                if (count > 1)
                        printf("\n"
                               "WARNING:\n"
                               "Multiple processes match the pattern. Monit will select the process with the\n"
                               "highest uptime, the one highlighted.\n");
        }
}


//FIXME: move to standalone system class
boolean_t init_system_info(void) {
        memset(&systeminfo, 0, sizeof(SystemInfo_T));
        gettimeofday(&systeminfo.collected, NULL);
        if (uname(&systeminfo.uname) < 0) {
                LogError("'%s' resource monitoring initialization error -- uname failed: %s\n", Run.system->name, STRERROR);
                return false;
        }
        systeminfo.total_cpu_user_percent = -1.;
        systeminfo.total_cpu_syst_percent = -1.;
        systeminfo.total_cpu_wait_percent = -1.;
        return (init_process_info_sysdep());
}


//FIXME: move to standalone system class
boolean_t update_system_info() {
        if (Run.flags & Run_ProcessEngineEnabled) {
                if (getloadavg_sysdep(systeminfo.loadavg, 3) == -1) {
                        LogError("'%s' statistic error -- load average gathering failed\n", Run.system->name);
                        goto error1;
                }

                if (! used_system_memory_sysdep(&systeminfo)) {
                        LogError("'%s' statistic error -- memory usage gathering failed\n", Run.system->name);
                        goto error2;
                }
                systeminfo.total_mem_percent  = systeminfo.mem_max > 0ULL ? (100. * (double)systeminfo.total_mem / (double)systeminfo.mem_max) : 0.;
                systeminfo.total_swap_percent = systeminfo.swap_max > 0ULL ? (100. * (double)systeminfo.total_swap / (double)systeminfo.swap_max) : 0.;

                if (! used_system_cpu_sysdep(&systeminfo)) {
                        LogError("'%s' statistic error -- cpu usage gathering failed\n", Run.system->name);
                        goto error3;
                }

                return true;
        }

error1:
        systeminfo.loadavg[0] = 0;
        systeminfo.loadavg[1] = 0;
        systeminfo.loadavg[2] = 0;
error2:
        systeminfo.total_mem = 0ULL;
        systeminfo.total_mem_percent = 0.;
        systeminfo.total_swap = 0ULL;
        systeminfo.total_swap_percent = 0.;
error3:
        systeminfo.total_cpu_user_percent = 0.;
        systeminfo.total_cpu_syst_percent = 0.;
        systeminfo.total_cpu_wait_percent = 0.;

        return false;
}


