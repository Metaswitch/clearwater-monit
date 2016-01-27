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

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifdef HAVE_SETJMP_H
#include <setjmp.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "monit.h"
#include "net.h"
#include "socket.h"
#include "base64.h"

// libmonit
#include "system/Time.h"
#include "exceptions/IOException.h"


/**
 *  Connect to a SMTP server and send mail.
 *
 *  @file
 */


/* ------------------------------------------------------------- Definitions */


typedef struct {
        Socket_T socket;
        boolean_t quit;
        MTAFlags_t flags;
        const char *server;
        int port;
        const char *username;
        const char *password;
        SslOptions_T ssl;
        char localhost[STRLEN];
} SendMail_T;


/* ----------------------------------------------------------------- Private */


void _request(SendMail_T *S, const char *s, ...) {
        va_list ap;
        va_start(ap,s);
        char *msg = Str_vcat(s, ap);
        va_end(ap);
        int rv = Socket_write(S->socket, msg, strlen(msg));
        FREE(msg);
        if (rv <= 0)
                THROW(IOException, "Error sending data to the server '%s' -- %s", S->server, STRERROR);
}


static void _response(SendMail_T *S) {
        int status = 0;
        char buf[STRLEN];
        do {
                if (! Socket_readLine(S->socket, buf, sizeof(buf)))
                        THROW(IOException, "Error receiving data from the mailserver '%s' -- %s", S->server, STRERROR);
                // Server features: 250[-|" "]<feature>
                if (Str_startsWith(buf, "250") && (buf[3] == '-' || buf[3] == ' ')) {
                        char *flag = buf + 4;
                        if (Str_startsWith(flag, "DSN")) {
                                S->flags |= MTA_DSN;
                        } else if (Str_startsWith(flag, "ETRN")) {
                                S->flags |= MTA_ETRN;
                        } else if (Str_startsWith(flag, "8BITMIME")) {
                                S->flags |= MTA_8BitMIME;
                        } else if (Str_startsWith(flag, "PIPELINING")) {
                                S->flags |= MTA_Pipelining;
                        } else if (Str_startsWith(flag, "ENHANCEDSTATUSCODES")) {
                                S->flags |= MTA_EnhancedStatusCodes;
                        } else if (Str_startsWith(flag, "STARTTLS")) {
                                S->flags |= MTA_StartTLS;
                        } else if (Str_startsWith(flag, "AUTH")) {
                                if (Str_sub(flag, " PLAIN"))
                                        S->flags |= MTA_AuthPlain;
                                if (Str_sub(flag, " LOGIN"))
                                        S->flags |= MTA_AuthLogin;
                        }
                }
        } while (buf[3] == '-'); // multi-line response
        Str_chomp(buf);
        if (sscanf(buf, "%d", &status) != 1 || status < 200 || status >= 400)
                THROW(IOException, "%s", buf);
}


static void _open(SendMail_T *S) {
        MailServer_T mta = Run.mailservers;
        if (mta) {
                S->server   = mta->host;
                S->port     = mta->port;
                S->username = mta->username;
                S->password = mta->password;
                S->ssl      = mta->ssl;
        } else {
                THROW(IOException, "No mail servers are defined -- see manual for 'set mailserver' statement");
        }
        do {
                // wait with ssl-connect if SSL_TLS* is set (RFC 3207)
                //FIXME: use ssl options ... SSL_TLS method doesn't automatically mean the SSL should be deferred
                //FIXME: implement new ssl option {startls: [false | true]}
                //FIXME: backward compatibility: set mailserver port 25 with ssl {version: tlsv1} ... if SMTPS connection failed, return error message with starttls:enable hint
                if (! S->ssl.use_ssl || S->ssl.version == SSL_TLSV1 || S->ssl.version == SSL_TLSV11 || S->ssl.version == SSL_TLSV12)
                        S->socket = Socket_new(S->server, S->port, Socket_Tcp, Socket_Ip, false, Run.mailserver_timeout);
                else
                        S->socket = Socket_create(S->server, S->port, Socket_Tcp, Socket_Ip, S->ssl, Run.mailserver_timeout);
                if (S->socket)
                        break;
                LogError("Cannot open a connection to the mailserver '%s:%i' -- %s\n", S->server, S->port, STRERROR);
                if (mta && (mta = mta->next)) {
                        S->server   = mta->host;
                        S->port     = mta->port;
                        S->username = mta->username;
                        S->password = mta->password;
                        S->ssl      = mta->ssl;
                        LogInfo("Trying the next mail server '%s:%i'\n", S->server, S->port);
                        continue;
                } else {
                        THROW(IOException, "No mail servers are available");
                }
        } while (true);
        S->quit = true;
}


static void _close(SendMail_T *S) {
        TRY
        {
                if (S->quit) {
                        S->quit = false;
                        _request(S, "QUIT\r\n");
                        _response(S);
                }
        }
        ELSE
        {
                LogError("Mail: %s\n", Exception_frame.message);
        }
        FINALLY
        {
                if (S->socket)
                        Socket_free(&(S->socket));
        }
        END_TRY;
}


/* ------------------------------------------------------------------ Public */


/**
 * Send mail messages via SMTP
 * @param mail A Mail object
 * @return false if failed, true if succeeded
 */
boolean_t sendmail(Mail_T mail) {
        SendMail_T S;
        boolean_t failed = false;
        char now[STRLEN];

        ASSERT(mail);

        memset(&S, 0, sizeof(S));

        TRY
        {
                _open(&S);
                Time_gmtstring(Time_now(), now);
                snprintf(S.localhost, sizeof(S.localhost), "%s", Run.mail_hostname ? Run.mail_hostname : Run.system->name);
                _response(&S);
                _request(&S, "EHLO %s\r\n", S.localhost);
                _response(&S);
                if (S.ssl.use_ssl && (S.ssl.version == SSL_TLSV1 || S.ssl.version == SSL_TLSV11 || S.ssl.version == SSL_TLSV12)) {
                        if (S.flags & MTA_StartTLS) {
                                _request(&S, "STARTTLS\r\n");
                                _response(&S);
                                TRY
                                {
                                        Socket_enableSsl(S.socket, S.ssl, NULL);
                                }
                                ELSE
                                {
                                        S.quit = false;
                                        RETHROW;
                                }
                                END_TRY;
                                /* After starttls, send ehlo again: RFC 3207: 4.2 Result of the STARTTLS Command */
                                _request(&S, "EHLO %s\r\n", S.localhost);
                                _response(&S);
                        } else {
                                THROW(IOException, "STARTTLS required but the mail server doesn't support it");
                        }
                }
                // Authenticate if possible
                if (S.username) {
                        char buffer[STRLEN];
                        // PLAIN takes precedence
                        if (S.flags & MTA_AuthPlain) {
                                int len = snprintf(buffer, STRLEN, "%c%s%c%s", '\0', S.username, '\0', S.password ? S.password : "");
                                char *b64 = encode_base64(len, (unsigned char *)buffer);
                                TRY
                                {
                                        _request(&S, "AUTH PLAIN %s\r\n", b64);
                                        _response(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                        } else if (S.flags & MTA_AuthLogin) {
                                _request(&S, "AUTH LOGIN\r\n");
                                _response(&S);
                                snprintf(buffer, STRLEN, "%s", S.username);
                                char *b64 = encode_base64(strlen(buffer), (unsigned char *)buffer);
                                TRY
                                {
                                        _request(&S, "%s\r\n", b64);
                                        _response(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                                snprintf(buffer, STRLEN, "%s", S.password ? S.password : "");
                                b64 = encode_base64(strlen(buffer), (unsigned char *)buffer);
                                TRY
                                {
                                        _request(&S, "%s\r\n", b64);
                                        _response(&S);
                                }
                                FINALLY
                                {
                                        FREE(b64);
                                }
                                END_TRY;
                        } else {
                                THROW(IOException, "Authentication failed -- no supported authentication methods found");
                        }
                }
                for (Mail_T m = mail; m; m = m->next) {
                        _request(&S, "MAIL FROM: <%s>\r\n", m->from);
                        _response(&S);
                        _request(&S, "RCPT TO: <%s>\r\n", m->to);
                        _response(&S);
                        _request(&S, "DATA\r\n");
                        _response(&S);
                        _request(&S, "From: %s\r\n", m->from);
                        if (m->replyto)
                                _request(&S, "Reply-To: %s\r\n", m->replyto);
                        _request(&S, "To: %s\r\n", m->to);
                        _request(&S, "Subject: %s\r\n", m->subject);
                        _request(&S, "Date: %s\r\n", now);
                        _request(&S, "X-Mailer: Monit %s\r\n", VERSION);
                        _request(&S, "MIME-Version: 1.0\r\n");
                        _request(&S, "Content-Type: text/plain; charset=\"iso-8859-1\"\r\n");
                        _request(&S, "Content-Transfer-Encoding: 8bit\r\n");
                        _request(&S, "Message-Id: <%lld.%lu@%s>\r\n", (long long)Time_now(), random(), S.localhost);
                        _request(&S, "\r\n");
                        _request(&S, "%s\r\n", m->message);
                        _request(&S, ".\r\n");
                        _response(&S);
                }
        }
        ELSE
        {
                failed = true;
                LogError("Mail: %s\n", Exception_frame.message);
        }
        FINALLY
        {
                _close(&S);
        }
        END_TRY;
        return failed;
}

