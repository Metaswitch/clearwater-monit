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

#include <stdio.h>

#include "monit.h"
#include "process.h"
#include "process_sysdep.h"

// libmonit
#include "system/Time.h"

/**
 *  General purpose /proc methods.
 *
 *  @file
 */


/* ----------------------------------------------------------------- Private */


/**
 * Search a leaf in the processtree
 * @param pid  pid of the process
 * @param pt  processtree
 * @param treesize  size of the processtree
 * @return process index if succeeded otherwise -1
 */
static int _findProcess(int pid, ProcessTree_T *pt, int treesize) {
        if (treesize > 0) {
                for (int i = 0; i < treesize; i++)
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


/* ------------------------------------------------------------------ Public */


/**
 * Initialize the proc information code
 * @return true if succeeded otherwise false.
 */
boolean_t init_process_info(void) {
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


/**
 * Get the proc infomation (CPU percentage, MEM in MByte and percent,
 * status), enduser version.
 * @param p A Service object
 * @param pid The process id
 * @return true if succeeded otherwise false.
 */
boolean_t update_process_data(Service_T s, ProcessTree_T *pt, int treesize, pid_t pid) {
        ASSERT(s);

        /* save the previous pid and set actual one */
        s->inf->priv.process._pid = s->inf->priv.process.pid;
        s->inf->priv.process.pid  = pid;

        int leaf = _findProcess(pid, pt, treesize);
        if (leaf != -1) {
                /* save the previous ppid and set actual one */
                s->inf->priv.process._ppid             = s->inf->priv.process.ppid;
                s->inf->priv.process.ppid              = pt[leaf].ppid;
                s->inf->priv.process.uid               = pt[leaf].cred.uid;
                s->inf->priv.process.euid              = pt[leaf].cred.euid;
                s->inf->priv.process.gid               = pt[leaf].cred.gid;
                s->inf->priv.process.uptime            = pt[leaf].uptime;
                s->inf->priv.process.threads           = pt[leaf].threads;
                s->inf->priv.process.children          = pt[leaf].children.total;
                s->inf->priv.process.zombie            = pt[leaf].zombie;
                s->inf->priv.process.cpu_percent       = pt[leaf].cpu.usage;
                s->inf->priv.process.total_cpu_percent = pt[leaf].cpu.usage_total > 100. ? 100. : pt[leaf].cpu.usage_total;
                s->inf->priv.process.mem               = pt[leaf].memory.usage;
                s->inf->priv.process.total_mem         = pt[leaf].memory.usage_total;
                if (systeminfo.mem_max > 0) {
                        s->inf->priv.process.total_mem_percent = pt[leaf].memory.usage_total >= systeminfo.mem_max ? 100. : (100. * (double)pt[leaf].memory.usage_total / (double)systeminfo.mem_max);
                        s->inf->priv.process.mem_percent       = pt[leaf].memory.usage >= systeminfo.mem_max ? 100. : (100. * (double)pt[leaf].memory.usage / (double)systeminfo.mem_max);
                }
        } else {
                Util_resetInfo(s);
        }
        return true;
}


/**
 * Updates the system wide statistic
 * @return true if successful, otherwise false
 */
boolean_t update_system_load() {
        if (Run.flags & Run_ProcessEngineEnabled) {
                if (getloadavg_sysdep(systeminfo.loadavg, 3) == -1) {
                        LogError("'%s' statistic error -- load average gathering failed\n", Run.system->name);
                        goto error1;
                }

                if (! used_system_memory_sysdep(&systeminfo)) {
                        LogError("'%s' statistic error -- memory usage gathering failed\n", Run.system->name);
                        goto error2;
                }
                systeminfo.total_mem_percent  = systeminfo.mem_max > 0 ? (100. * (double)systeminfo.total_mem / (double)systeminfo.mem_max) : 0.;
                systeminfo.total_swap_percent = systeminfo.swap_max > 0 ? (100. * (double)systeminfo.total_swap / (double)systeminfo.swap_max) : 0.;

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
error3:
        systeminfo.total_cpu_user_percent = 0.;
        systeminfo.total_cpu_syst_percent = 0.;
        systeminfo.total_cpu_wait_percent = 0.;

        return false;
}


/**
 * Initialize the process tree
 * @return treesize >= 0 if succeeded otherwise < 0
 */
int initprocesstree(ProcessTree_T **pt_r, int *size_r, ProcessEngine_Flags pflags) {
        ASSERT(pt_r);
        ASSERT(size_r);

        ProcessTree_T *oldpt = *pt_r;
        int oldsize = *size_r;
        if (oldpt) {
                *pt_r = NULL;
                *size_r = 0;
                // We need only process' cpu.time from the old ptree, so free dynamically allocated parts which we don't need before initializing new ptree (so the memory can be reused, otherwise the memory footprint will hold two ptrees)
                for (int i = 0; i < oldsize; i++) {
                        FREE(oldpt[i].cmdline);
                        FREE(oldpt[i].children.list);
                }
        }

        systeminfo.time_prev = systeminfo.time;
        systeminfo.time = Time_milli() / 100.;
        if ((*size_r = initprocesstree_sysdep(pt_r, pflags)) <= 0 || ! *pt_r) {
                DEBUG("System statistic -- cannot initialize the process tree -- process resource monitoring disabled\n");
                Run.flags &= ~Run_ProcessEngineEnabled;
                if (oldpt)
                        delprocesstree(&oldpt, &oldsize);
                return -1;
        } else if (! (Run.flags & Run_ProcessEngineEnabled)) {
                DEBUG("System statistic -- initialization of the process tree succeeded -- process resource monitoring enabled\n");
                Run.flags |= Run_ProcessEngineEnabled;
        }

        int root = -1; // Main process. Not all systems have main process with PID 1 (such as Solaris zones and FreeBSD jails), so we try to find process which is parent of itself
        ProcessTree_T *pt = *pt_r;
        double time_delta = systeminfo.time - systeminfo.time_prev;
        for (int i = 0; i < (volatile int)*size_r; i ++) {
                if (oldpt) {
                        int oldentry = _findProcess(pt[i].pid, oldpt, oldsize);
                        if (oldentry != -1)
                                pt[i].cpu.usage = _cpuUsage(&pt[i], &oldpt[oldentry], time_delta);
                }
                // Note: on DragonFly, main process is swapper with pid 0 and ppid -1, so take also this case into consideration
                if ((pt[i].pid == pt[i].ppid) || (pt[i].ppid == -1)) {
                        root = pt[i].parent = i;
                } else {
                        // Find this process' parent
                        int parent = _findProcess(pt[i].ppid, pt, *size_r);
                        if (parent == -1) {
                                /* Parent process wasn't found - on Linux this is normal: main process with PID 0 is not listed, similarly in FreeBSD jail.
                                 * We create virtual process entry for missing parent so we can have full tree-like structure with root. */
                                parent = (*size_r)++;
                                pt = RESIZE(*pt_r, *size_r * sizeof(ProcessTree_T));
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
        FREE(oldpt); // Free the rest of old ptree
        if (root == -1) {
                DEBUG("System statistic error -- cannot find root process id\n");
                delprocesstree(pt_r, size_r);
                return -1;
        }

        _fillProcessTree(pt, root);

        return *size_r;
}


time_t getProcessUptime(pid_t pid, ProcessTree_T *pt, int treesize) {
        if (pt) {
                int leaf = _findProcess(pid, pt, treesize);
                return (time_t)((leaf >= 0 && leaf < treesize) ? pt[leaf].uptime : -1);
        } else {
                return 0;
        }
}


/**
 * Delete the process tree
 */
void delprocesstree(ProcessTree_T **reference, int *size) {
        ProcessTree_T *pt = *reference;
        if (pt) {
                for (int i = 0; i < *size; i++) {
                        FREE(pt[i].cmdline);
                        FREE(pt[i].children.list);
                }
                FREE(pt);
                *reference = NULL;
                *size = 0;
        }
}


void process_testmatch(char *pattern) {
#ifdef HAVE_REGEX_H
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
#endif
        initprocesstree(&ptree, &ptreesize, ProcessEngine_CollectCommandLine);
        if (Run.flags & Run_ProcessEngineEnabled) {
                int count = 0;
                printf("List of processes matching pattern \"%s\":\n", pattern);
                printf("------------------------------------------\n");
                for (int i = 0; i < ptreesize; i++) {
                        boolean_t match = false;
                        if (ptree[i].cmdline && ! strstr(ptree[i].cmdline, "procmatch")) {
#ifdef HAVE_REGEX_H
                                match = regexec(regex_comp, ptree[i].cmdline, 0, NULL, 0) ? false : true;
#else
                                match = strstr(ptree[i].cmdline, pattern) ? true : false;
#endif
                                if (match) {
                                        printf("\t%s\n", ptree[i].cmdline);
                                        count++;
                                }
                        }
                }
                printf("------------------------------------------\n");
                printf("Total matches: %d\n", count);
                if (count > 1)
                        printf("WARNING: multiple processes matched the pattern. The check is FIRST-MATCH based, please refine the pattern\n");
        }
}


/**
 * Reads an process dependent entry or the proc filesystem
 * @param buf buffer to write to
 * @param buf_size size of buffer "buf"
 * @param name name of proc service
 * @param pid number of the process / or <0 if main directory
 * @param bytes_read number of bytes read to buffer
 * @return true if succeeded otherwise false.
 */
boolean_t read_proc_file(char *buf, int buf_size, char *name, int pid, int *bytes_read) {
        ASSERT(buf);
        ASSERT(name);

        char filename[STRLEN];
        if (pid < 0)
                snprintf(filename, sizeof(filename), "/proc/%s", name);
        else
                snprintf(filename, sizeof(filename), "/proc/%d/%s", pid, name);

        int fd = open(filename, O_RDONLY);
        if (fd < 0) {
                DEBUG("Cannot open proc file %s -- %s\n", filename, STRERROR);
                return false;
        }

        boolean_t rv = false;
        int bytes = (int)read(fd, buf, buf_size - 1);
        if (bytes >= 0) {
                if (bytes_read)
                        *bytes_read = bytes;
                buf[bytes] = 0;
                rv = true;
        } else {
                DEBUG("Cannot read proc file %s -- %s\n", filename, STRERROR);
        }

        if (close(fd) < 0)
                LogError("proc file %s close failed -- %s\n", filename, STRERROR);

        return rv;
}

