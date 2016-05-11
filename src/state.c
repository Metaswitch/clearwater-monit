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

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif



#include "monit.h"
#include "state.h"

// libmonit
#include "exceptions/IOException.h"


/**
 * The list of persistent properties:
 *
 *    1.) service name + service type
 *        Monit configuration may change, so the state restore needs to ignore
 *        the removed services or services which type doesn't match (the
 *        service name was reused for different check). The current service
 *        runtime is thus paired with the saved service state by name and type.
 *
 *    2.) monitoring state
 *        Keep the monitoring enabled or disabled on Monit restart. Useful for
 *        example when Monit is running in active/passive cluster, so the
 *        service monitoring mode doesn't reset when Monit needs to be reloaded
 *        and the service won't enter unwanted passive/passive or active/active
 *        state on multiple hosts. Another example is service which timed out
 *        due to excessive errors or the monitoring was intentionally disabled
 *        by admin for maintenance - do not re-enable monitoring on Monit reload.
 *
 *    3.) service restart counters
 *
 *    4.) inode number and read position for the file check
 *        Allows to skip the content match test for the content which was checked
 *        already to suppress duplicate events.
 *
 *    5.) size, checksum, timestamp, permissions, link speed, filesystem flags
 *        for the change observation test
 *
 * Data is stored in binary form in the statefile using the following format:
 *    <MAGIC><VERSION>{<SERVICE_STATE>}+
 *
 * When the persistent field needs to be added, update the State_Version along
 * with State_restore() and State_save(). The version allows to recognize the
 * service state structure and file format.
 *
 * The backward compatibility of monitoring state restore is very important if
 * Monit runs in cluster => keep previous formats compatibility.
 *
 * @file
 */


/* ------------------------------------------------------------- Definitions */


/* Extended format version */
typedef enum {
        StateVersion0 = 0,
        StateVersion1,
        StateVersion2,
        StateVersion3
} State_Version;


/* Extended format version 3 */
typedef struct mystate3 {
        char               name[STRLEN];
        int                type;
        int                monitor;
        int                nstart;
        int                ncycle;
        union {
                struct {
                        time_t timestamp;
                        int mode;
                } directory;

                struct {
                        unsigned long long inode;
                        unsigned long long readpos;
                        unsigned long long size;
                        unsigned long long timestamp;
                        int mode;
                        MD_T hash;
                } file;

                struct {
                        unsigned long long timestamp;
                        int mode;
                } fifo;

                struct {
                        int mode;
                        int flags;
                } filesystem;

                struct {
                        int duplex;
                        long long speed;
                        //FIXME: when Link API is moved from libmonit to monit, save also link bytes in/out and packets in/out history, so the network statistics is not reset on each monit reload
                } net;
        } priv;
} State3_T;


/* Extended format version 2 (in V3 only a system boot time was added to state header, otherwise the V2 service state is identical to V3) */
typedef struct mystate3 State2_T;


/* Extended format version 1 */
typedef struct mystate1 {
        char               name[STRLEN];
        int                type;
        int                monitor;
        int                nstart;
        int                ncycle;
        union {
                struct {
                        unsigned long long inode;
                        unsigned long long readpos;
                } file;
        } priv;
} State1_T;


/* Format version 0 (Monit <= 5.3) */
typedef struct mystate0 {
        char               name[STRLEN];
        int                mode;                // obsolete since Monit 5.1
        int                nstart;
        int                ncycle;
        int                monitor;
        unsigned long long error;               // obsolete since Monit 5.0
} State0_T;


static int file = -1;
static uint64_t booted = 0ULL;


/* ----------------------------------------------------------------- Private */


static void _updateStart(Service_T S, int nstart, int ncycle) {
        S->nstart = nstart;
        S->ncycle = ncycle;
}


static void _updateMonitor(Service_T S, Monitor_State monitor) {
        if (systeminfo.booted == booted || S->onreboot == Onreboot_Laststate) {
                // Monit reload or restart within the same boot session OR persistent state => restore the monitoring state
                if (monitor == Monitor_Not)
                        S->monitor = Monitor_Not;
                else if (S->monitor == Monitor_Not)
                        S->monitor = Monitor_Init;
        } else {
                // System rebooted
                if (S->onreboot == Onreboot_Nostart)
                        S->monitor = Monitor_Not;
                else
                        S->monitor = Monitor_Init;
        }
}


static void _updateFilePosition(Service_T S, unsigned long long inode, unsigned long long readpos) {
        S->inf->priv.file.inode = (ino_t)inode;
        S->inf->priv.file.readpos = (off_t)readpos;
}


static void _updateTimestamp(Service_T S, unsigned long long timestamp) {
        for (Timestamp_T t = S->timestamplist; t; t = t->next) {
                if (t->test_changes) {
                        t->timestamp = (time_t)timestamp;
                        t->initialized = true;
                }
        }
}


static void _updatePermission(Service_T S, int mode) {
        if (S->perm && S->perm->test_changes)
                S->perm->perm = mode;
}


static void _updateSize(Service_T S, unsigned long long size) {
        for (Size_T s = S->sizelist; s; s = s->next) {
                if (s->test_changes) {
                        s->size = size;
                        s->initialized = true;
                }
        }
}


static void _updateChecksum(Service_T S, char *hash) {
        if (S->checksum && S->checksum->test_changes) {
                S->checksum->initialized = false;
                strncpy(S->checksum->hash, hash, sizeof(S->checksum->hash));
        }
}


static void _updateFilesystemFlags(Service_T S, int flags) {
        if (S->fsflaglist)
                S->inf->priv.filesystem.flags = flags;
}


static void _updateLinkSpeed(Service_T S, int duplex, long long speed) {
        for (LinkSpeed_T l = S->linkspeedlist; l; l = l->next) {
                l->duplex = duplex;
                l->speed = speed;
        }
}


static void _restoreV3() {
        // System header
        if (read(file, &booted, sizeof(booted)) != sizeof(booted))
                THROW(IOException, "Unable to read system boot time");
        // Services state
        State3_T state;
        while (read(file, &state, sizeof(state)) == sizeof(state)) {
                Service_T service = Util_getService(state.name);
                if (service && service->type == state.type) {
                        _updateStart(service, state.nstart, state.ncycle);
                        _updateMonitor(service, state.monitor);
                        switch (service->type) {
                                case Service_Directory:
                                        _updatePermission(service, state.priv.directory.mode);
                                        _updateTimestamp(service, state.priv.directory.timestamp);
                                        break;

                                case Service_Fifo:
                                        _updatePermission(service, state.priv.fifo.mode);
                                        _updateTimestamp(service, state.priv.fifo.timestamp);
                                        break;

                                case Service_File:
                                        _updatePermission(service, state.priv.file.mode);
                                        _updateTimestamp(service, state.priv.file.timestamp);
                                        _updateFilePosition(service, state.priv.file.inode, state.priv.file.readpos);
                                        _updateSize(service, state.priv.file.size);
                                        _updateChecksum(service, state.priv.file.hash);
                                        break;

                                case Service_Filesystem:
                                        _updatePermission(service, state.priv.filesystem.mode);
                                        _updateFilesystemFlags(service, state.priv.filesystem.flags);
                                        break;

                                case Service_Net:
                                        _updateLinkSpeed(service, state.priv.net.duplex, state.priv.net.speed);
                                        break;

                                default:
                                        break;
                        }
                }
        }
}


static void _restoreV2() {
        // System header
        booted = systeminfo.booted; // No boot time available => for backward compatibility, act as if the system was not rebooted, as we don't know if monit was only restarted or machine rebooted
        // Services state
        State2_T state;
        while (read(file, &state, sizeof(state)) == sizeof(state)) {
                Service_T service = Util_getService(state.name);
                if (service && service->type == state.type) {
                        _updateStart(service, state.nstart, state.ncycle);
                        _updateMonitor(service, state.monitor);
                        switch (service->type) {
                                case Service_Directory:
                                        _updatePermission(service, state.priv.directory.mode);
                                        _updateTimestamp(service, state.priv.directory.timestamp);
                                        break;

                                case Service_Fifo:
                                        _updatePermission(service, state.priv.fifo.mode);
                                        _updateTimestamp(service, state.priv.fifo.timestamp);
                                        break;

                                case Service_File:
                                        _updatePermission(service, state.priv.file.mode);
                                        _updateTimestamp(service, state.priv.file.timestamp);
                                        _updateFilePosition(service, state.priv.file.inode, state.priv.file.readpos);
                                        _updateSize(service, state.priv.file.size);
                                        _updateChecksum(service, state.priv.file.hash);
                                        break;

                                case Service_Filesystem:
                                        _updatePermission(service, state.priv.filesystem.mode);
                                        _updateFilesystemFlags(service, state.priv.filesystem.flags);
                                        break;

                                case Service_Net:
                                        _updateLinkSpeed(service, state.priv.net.duplex, state.priv.net.speed);
                                        break;

                                default:
                                        break;
                        }
                }
        }
}


static void _restoreV1() {
        // System header
        booted = systeminfo.booted; // No boot time available => for backward compatibility, act as if the system was not rebooted, as we don't know if monit was only restarted or machine rebooted
        // Services state
        State1_T state;
        while (read(file, &state, sizeof(state)) == sizeof(state)) {
                Service_T service = Util_getService(state.name);
                if (service && service->type == state.type) {
                        _updateStart(service, state.nstart, state.ncycle);
                        _updateMonitor(service, state.monitor);
                        if (service->type == Service_File)
                                _updateFilePosition(service, state.priv.file.inode, state.priv.file.readpos);
                }
        }
}


static void _restoreV0(int services) {
        // System header
        booted = systeminfo.booted; // No boot time available => for backward compatibility, act as if the system was not rebooted, as we don't know if monit was only restarted or machine rebooted
        // Services state
        for (int i = 0; i < services; i++) {
                State0_T state;
                if (read(file, &state, sizeof(state)) != sizeof(state))
                        THROW(IOException, "Unable to read service state");
                Service_T service = Util_getService(state.name);
                if (service) {
                        _updateStart(service, state.nstart, state.ncycle);
                        _updateMonitor(service, state.monitor);
                }
        }
}


/* ------------------------------------------------------------------ Public */


boolean_t State_open() {
        State_close();
        if ((file = open(Run.files.state, O_RDWR | O_CREAT, 0600)) == -1) {
                LogError("State file '%s': cannot open for write -- %s\n", Run.files.state, STRERROR);
                return false;
        }
        atexit(State_close);
        return true;
}


void State_close() {
        if (file != -1) {
                if (close(file) == -1)
                        LogError("State file '%s': close error -- %s\n", Run.files.state, STRERROR);
                else
                        file = -1;
        }
}


void State_save() {
        TRY
        {
                if (ftruncate(file, 0L) == -1)
                        THROW(IOException, "Unable to truncate");
                if (lseek(file, 0L, SEEK_SET) == -1)
                        THROW(IOException, "Unable to seek");
                int magic = 0;
                if (write(file, &magic, sizeof(magic)) != sizeof(magic))
                        THROW(IOException, "Unable to write magic");
                // Save always using the latest format version
                int version = StateVersion3;
                if (write(file, &version, sizeof(version)) != sizeof(version))
                        THROW(IOException, "Unable to write format version");
                if (write(file, &systeminfo.booted, sizeof(systeminfo.booted)) != sizeof(systeminfo.booted))
                        THROW(IOException, "Unable to write system boot time");
                for (Service_T service = servicelist; service; service = service->next) {
                        State3_T state;
                        memset(&state, 0, sizeof(state));
                        snprintf(state.name, sizeof(state.name), "%s", service->name);
                        state.type = service->type;
                        state.monitor = service->monitor & ~Monitor_Waiting;
                        state.nstart = service->nstart;
                        state.ncycle = service->ncycle;
                        switch (service->type) {
                                case Service_Directory:
                                        state.priv.directory.timestamp = (unsigned long long)service->inf->priv.directory.timestamp;
                                        if (service->perm)
                                                state.priv.directory.mode = service->perm->perm;
                                        break;

                                case Service_Fifo:
                                        state.priv.fifo.timestamp = (unsigned long long)service->inf->priv.fifo.timestamp;
                                        if (service->perm)
                                                state.priv.fifo.mode = service->perm->perm;
                                        break;

                                case Service_File:
                                        state.priv.file.inode = service->inf->priv.file.inode;
                                        state.priv.file.readpos = service->inf->priv.file.readpos;
                                        state.priv.file.size = (unsigned long long)service->inf->priv.file.size;
                                        state.priv.file.timestamp = (unsigned long long)service->inf->priv.file.timestamp;
                                        if (service->checksum)
                                                strncpy(state.priv.file.hash, service->inf->priv.file.cs_sum, sizeof(state.priv.file.hash));
                                        if (service->perm)
                                                state.priv.file.mode = service->perm->perm;
                                        break;

                                case Service_Filesystem:
                                        if (service->perm)
                                                state.priv.filesystem.mode = service->perm->perm;
                                        state.priv.filesystem.flags = service->inf->priv.filesystem.flags;
                                        break;

                                case Service_Net:
                                        if (service->linkspeedlist) {
                                                state.priv.net.duplex = service->linkspeedlist->duplex;
                                                state.priv.net.speed = service->linkspeedlist->speed;
                                        }
                                        break;

                                default:
                                        break;
                        }
                        if (write(file, &state, sizeof(state)) != sizeof(state))
                                THROW(IOException, "Unable to write service state");
                }
                if (fsync(file))
                        THROW(IOException, "Unable to sync -- %s", STRERROR);
        }
        ELSE
        {
                LogError("State file '%s': %s\n", Run.files.state, Exception_frame.message);
        }
        END_TRY;
}


void State_restore() {
        /* Ignore empty state file */
        if ((lseek(file, 0L, SEEK_END) == 0))
                return;
        TRY
        {
                if (lseek(file, 0L, SEEK_SET) == -1)
                        THROW(IOException, "Unable to seek");
                int magic;
                if (read(file, &magic, sizeof(magic)) != sizeof(magic))
                        THROW(IOException, "Unable to read magic");
                if (magic > 0) {
                        // The statefile format of Monit <= 5.3, the magic is number of services, followed by State0_T structures
                        _restoreV0(magic);
                } else {
                        // The extended statefile format (Monit >= 5.4)
                        int version;
                        if (read(file, &version, sizeof(version)) != sizeof(version))
                                THROW(IOException, "Unable to read version");
                        switch (version) {
                                case StateVersion1:
                                        _restoreV1();
                                        break;
                                case StateVersion2:
                                        _restoreV2();
                                        break;
                                case StateVersion3:
                                        _restoreV3();
                                        break;
                                default:
                                        LogWarning("State file '%s': incompatible version %d\n", Run.files.state, version);
                                        break;
                        }
                }
        }
        ELSE
        {
                LogError("State file '%s': %s\n", Run.files.state, Exception_frame.message);
        }
        END_TRY;
}

