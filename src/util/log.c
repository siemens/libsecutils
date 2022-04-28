/** 
* @file log.c
* 
* @brief Logging facility which, by default, outputs to syslog and console
*
* @copyright Copyright (c) Siemens Mobility GmbH, 2021
*
* @author David von Oheimb <david.von.oheimb@siemens.com>
*
* This work is licensed under the terms of the Apache Software License 
* 2.0. See the COPYING file in the top-level directory.
*
* SPDX-License-Identifier: Apache-2.0
*/

#include <util/util.h>
#include <util/log.h>

#include <operators.h>

#include <syslog.h>

#include <assert.h>

// use the GNU-specific `strerror_r`
// https://man7.org/linux/man-pages/man3/strerror.3.html : SYNOPSIS
#define _GNU_SOURCE

static LOG_cb_t LOG_fn = 0; /*!< this variable is shared between threads */
static const size_t loc_len = 256;

static severity verbosity = LOG_INFO;

BIO* bio_err = 0;
BIO* bio_trace = 0;

static const char* app_name = "secutils"; /* copied as workaround for gcc 6; should be: UTIL_SECUTILS_NAME */

__attribute__ ((constructor))
static void sec_open_log(void)
{
    LOG_init(0);
}

__attribute__ ((destructor))
static void sec_close_log(void)
{
    LOG_close();
}

void LOG_init(OPTIONAL LOG_cb_t log_fn)
{
    LOG_close(); /* flush any pending output and free any previous resources */

    if(log_fn not_eq 0)
    {
        LOG_fn = log_fn;
    }
}

static void log_close_bios(void)
{
    if(bio_trace not_eq 0)
    {
        (void)BIO_flush(bio_trace);
        BIO_free(bio_trace);
        bio_trace = 0;
    }
    if(bio_err not_eq 0)
    {
        (void)BIO_flush(bio_err);
        BIO_free(bio_err);
        bio_err = 0;
    }
}

void LOG_close(void)
{
    log_close_bios();
}

void LOG_set_verbosity(severity level)
{
    if(level < LOG_EMERG or level > LOG_TRACE)
    {
        fprintf(stderr, "error: logging verbosity level %d out of range (0 .. 8) for %s\n", level, app_name);
        return;
    }

    log_close_bios();

    verbosity = level;

#ifndef NDEBUG
    if(level >= LOG_ERR)
    {
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
        if(bio_err is_eq 0)
        {
                fprintf(stderr, "warning: cannot open bio_err for low-level error reporting of %s\n", app_name);
        }
    }
    if(level >= LOG_TRACE)
    {
        bio_trace = BIO_new_fp(stdout, BIO_NOCLOSE);
        if(bio_trace is_eq 0)
        {
                fprintf(stderr, "warning: cannot open bio_trace for detailed debugging output of %s\n", app_name);
        }
    }
#endif
}

void LOG_set_name(OPTIONAL const char* name)
{
    app_name = name not_eq 0 ? name : UTIL_SECUTILS_NAME;
}

bool LOG_default(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level, const char* msg)
{
    return LOG_generic(func, file, lineno, level, msg, 1, 1);
}

bool LOG_console(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level, const char* msg)
{
    return LOG_generic(func, file, lineno, level, msg, 0, 1);
}

bool LOG_generic(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level, const char* msg, bool use_syslog, bool use_console)
{
    const unsigned long u_func = (unsigned long)func;
    const unsigned long u_file = (unsigned long)file;
    const unsigned long u_msg = (unsigned long)msg;
    if(u_func < 0x400 or u_file < 0x400 or u_msg < 0x400 or (unsigned)lineno > 10000 or (unsigned)level > LOG_TRACE)
    {
        fprintf(stderr,
                "### %s() has been called with illegal arguments: func=0x%lx file=0x%lx lineno=%d level=%d msg=0x%lx, "
                "likely due to library version mismatch ###\n",
                OPENSSL_FUNC, u_func, u_file, lineno, level, u_msg);
        return false;
    }

    if(level > verbosity
#ifdef NDEBUG
    /* output DEBUG level messages only if debugging is enabled at build time */
    or level >= LOG_DEBUG
#endif
      )
    {
        return true;
    }

    if(func is_eq 0)
    {
        func = "(no function)";
    }
    if(file is_eq 0)
    {
        file = "(no file)";
    }
    if(msg is_eq 0) /* just in case */
    {
        msg = "(no message)";
    }

    if(use_syslog)
    {
        syslog(level, "%s: %.50s():%.60s:%d: %.256s", app_name, func, file, lineno, msg);
    }

    if(not use_console)
    {
        return true;
    }

    /* print everything to stdout in order to prevent order mismatch with portions on stderr */
    FILE* fd = /* level <= LOG_WARNING ? stderr : */ stdout;

    char loc[loc_len];
    memset(loc, 0x00, loc_len);
    int len = snprintf(loc, sizeof(loc), "%s", app_name);
#ifndef NDEBUG
    /* print function name, source file name, and line number only if debugging is enabled at build time */
    (void)snprintf(loc + len, sizeof(loc) - len, ":%s():%s:%d:", func, file, lineno);
#endif

    /* print string corresponding to level */
    char* lvl = 0;
    switch(level)
    {
        case LOG_EMERG:
            lvl = "EMERGENCY";
            break;
        case LOG_ALERT:
            lvl = "ALERT";
            break;
        case LOG_CRIT:
            lvl = "CRITICAL";
            break;
        case LOG_ERR:
            lvl = "ERROR";
            break;
        case LOG_WARNING:
            lvl = "WARNING";
            break;
        case LOG_NOTICE:
            lvl = "NOTICE";
            break;
        case LOG_INFO:
            lvl = "INFO";
            break;
        case LOG_DEBUG:
            lvl = "DEBUG";
            break;
        case LOG_TRACE:
            lvl = "TRACE";
            break;
        default:
            lvl = "(UNKNOWN SEVERITY)";
            break;
    }

    /* print message, making sure that newline is printed  */
    len = strlen(msg);
    const int msg_nl = len > 0 and msg[len - 1] is_eq '\n';
    const int ret = fprintf(fd, "%s %s: %s%s", loc, lvl, msg, msg_nl ? "" : "\n");

    /* make sure that printing is done right away, return info on success  */
    return fflush(fd) not_eq EOF and ret >= 0;
}


/*
 * Function used for outputting error/warn/debug messages depending on callback.
 * If no specific callback function is set, the function LOG_default() is used.
 */
bool LOG(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level, const char* fmt, ...)
{
    va_list arg_ptr;
    char msg[1024];
    bool res;

    va_start(arg_ptr, fmt);
    BIO_vsnprintf(msg, sizeof(msg), fmt, arg_ptr);
    res = (LOG_fn ? *LOG_fn : &LOG_default)(func, file, lineno, level, msg);
    va_end(arg_ptr);
    return res;
}

bool LOG_system_debug(int errnum)
{
    // https://man7.org/linux/man-pages/man3/strerror.3.html : NOTES
    char buffer[1024];
    const char messageTooLong[] = "... <error message too long!>";
    assert(sizeof(buffer) >= sizeof(messageTooLong));

    const int errnoBak = errno;

    errno = 0;

    // https://man7.org/linux/man-pages/man3/strerror.3.html : RETURN VALUE
    const char *message = "";
    message = strerror_r(errnum, buffer, sizeof(buffer));
    bool result = 0 is_eq errno;

    if (ERANGE is_eq errno)
    {
        // I guess, they are not so stupid to return `ERANGE` if `buffer` stays unused...
        (void)memcpy((void *)(buffer + (sizeof(buffer) - sizeof(messageTooLong))), (const void *)messageTooLong, sizeof(messageTooLong));
    }

    result = result and LOG(FL_DEBUG, "system error info: 'errno' = %i, '%s'", errnum, message);

    // must stay after calling LOG; LOG may change errno
    errno = errnoBak;
    return result;
}
