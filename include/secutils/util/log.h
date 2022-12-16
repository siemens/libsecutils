/** 
* @file log.h
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

#ifndef SECUTILS_LOG_H_
#define SECUTILS_LOG_H_

#include "util.h"

extern BIO* bio_err; /* for low-level error output if verbosity >= LOG_DEBUG */
extern BIO* bio_trace; /* for detailed debugging output if verbosity >= LOG_TRACE */

/*!< log levels resemble those of syslog.h but have one more entry: LOG_TRACE */
/* this type is part of the genCMPClient API */
typedef int severity;
#define LOG_EMERG   0  /*!< A panic condition was reported to all processes */
#define LOG_ALERT   1  /*!< A condition that should be corrected immediately */
#define LOG_CRIT    2  /*!< A critical condition */
#define LOG_ERR     3  /*!< An error message */
#define LOG_WARNING 4  /*!< A warning message */
#define LOG_NOTICE  5  /*!< A condition requiring special handling */
#define LOG_INFO    6  /*!< A general information message */
#define LOG_DEBUG   7  /*!< A message useful for debugging programs */
#define LOG_TRACE   8  /*!< A verbose message useful for detailed debugging */

/*!
 * @brief The type of the log callback function
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param msg the message text
 * @return true success and false on failure
 */
/* this type is part of the genCMPClient API */
typedef bool (*LOG_cb_t)(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                         const char* msg);

/*!
 * @brief initialize the logging functionality of libsecutils
 * @note this function may be called multiple times
 * @note this function does not affect the application name optionally set by LOG_set_name()
 *
 * @param log_fn the callback function to use for outputting log messages, or null to keep the current one.
 * @note by default, output is sent to syslog and the console (stdout).
 * @warning security note: the \p log_fn reporting function must be compliant with
 * https://wiki.sei.cmu.edu/confluence/display/c/FIO30-C.+Exclude+user+input+from+format+strings
 */
/* this function is used by the genCMPClient API implementation */
void LOG_init(OPTIONAL LOG_cb_t log_fn);

/*!
 * @brief flush any pending log output and de-initialize log-related resources
 * @note this function may be called multiple times
 */
/* this function is part of the genCMPClient API */
void LOG_close(void);

/*!
 * @brief set verbosity level of LOG_default()
 * @note this may be done before LOG_init() is called
 *
 * @param level the minimal severity of messages to be printed; default: LOG_INFO
 */
/* this function is used by the genCMPClient CLI implementation */
void LOG_set_verbosity(severity level);

/*!
 * @brief set the application name used by LOG_default()
 * @note this may be done before LOG_init() is called
 *
 * @param name the name to use, or null for the default: UTIL_SECUTILS_NAME
 * @note the active name must not be deallocated as long as logging is used
 */
/* this function is used by the genCMPClient CLI implementation */
void LOG_set_name(OPTIONAL const char* name);

/*!
 * @brief default logging output behavior: send to syslog and print to console (stdout)
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param msg the message text
 * @return true success and false on failure
 *
 * @par Thread safety
 * Logging a single message as a whole is thread safe.
 * However, the order of messages written to the syslog may vary and the order of
 * the messages written to the console may not match that of the syslog under race conditions.
 */
bool LOG_default(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                 const char* msg);

/*!
 * @brief as before, but print to console (stdout) only, do not send to syslog
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param msg the message text
 * @return true success and false on failure
 */
bool LOG_console(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                 const char* msg);

/*!
 * @brief generic logging output behavior: optionally send to syslog and/or console
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param msg the message text
 * @param use_syslog enable sending to syslog
 * @param use_console enable printing to console (stdout)
 * @return true success and false on failure
 */
bool LOG_generic(OPTIONAL const char* func, OPTIONAL const char* file, int lineno, severity level,
                 const char* msg, bool use_console, bool use_syslog);

/*!
 * @brief log an alert/error/warning/note/info/debug/trace message
 * @param func the name of the reporting function or component, or null
 * @param file the current source file path name, or null
 * @param lineno the current line number, or 0
 * @param level the nature of the message, i.e., its severity level
 * @param fmt format string B<fmt> with variable number of arguments as with printf determining the message text
 * @return true success and false on failure
 *
 * @par Thread safety
 * Logging a single message is thread safe as long as the \p func callback is thread safe.
 * However, the order of logged messages may not be preserved under race conditions.
 */
/* this function is used by the genCMPClient API implementation */
bool LOG(OPTIONAL const char *func, OPTIONAL const char *file, int lineno, severity level, const char *fmt,
         ...);
/*! Logs system error message with priority LOG_DEBUG
 *
 * @param errnum the system \c errno
 * @return \c true on success and \c false on failure
 *
 * @par Errors
 * @parblock
 * On error returns \c false. Keeps the system \c errno unchanged.
 *
 * There is nothing much to do about a failure of this method; the return value is mostly for debug purposes.
 *
 * The error conditions include: an invalid \p errnum parameter, too long error message, a failure of the LOG fuction.
 * @endparblock
 *
 * @par Thread safety
 * See LOG()
 *
 * @sa https://man7.org/linux/man-pages/man3/errno.3.html
 */
bool LOG_system_debug(int errnum);

# ifndef OPENSSL_FUNC
#  if defined(__STDC_VERSION__)
#   if __STDC_VERSION__ >= 199901L
#    define OPENSSL_FUNC __func__ /* function name is only available starting from C99.*/
/* Trying platform-specific and compiler-specific alternatives as fallback if possible. */
#   elif defined(__GNUC__) && __GNUC__ >= 2
#    define OPENSSL_FUNC __FUNCTION__
#   endif
#  elif defined(_MSC_VER)
#    define OPENSSL_FUNC __FUNCTION__
#  endif
/* If all these possibilities are exhausted, we give up and use a static string. */
#  ifndef OPENSSL_FUNC
#   define OPENSSL_FUNC "(unknown function)"
#  endif
# endif

#define LOG_FUNC_FILE_LINE OPENSSL_FUNC, OPENSSL_FILE, OPENSSL_LINE
#define FL_EMERG LOG_FUNC_FILE_LINE, LOG_EMERG  /*!< A panic condition was reported to all processes. */
#define FL_ALERT LOG_FUNC_FILE_LINE, LOG_ALERT  /*!< A condition that should be corrected immediately. */
#define FL_FATAL FL_ALERT                       /*!< A condition that should be corrected immediately. */
#define FL_CRIT LOG_FUNC_FILE_LINE, LOG_CRIT    /*!< A critical condition. */
#define FL_ERR LOG_FUNC_FILE_LINE, LOG_ERR      /*!< An error message. */
#define FL_WARN LOG_FUNC_FILE_LINE, LOG_WARNING /*!< A warning message. */
#define FL_NOTE LOG_FUNC_FILE_LINE, LOG_NOTICE  /*!< A condition requiring special handling. */
#define FL_INFO LOG_FUNC_FILE_LINE, LOG_INFO    /*!< A general information message. */
#define FL_DEBUG LOG_FUNC_FILE_LINE, LOG_DEBUG  /*!< A message useful for debugging. */
#define FL_TRACE LOG_FUNC_FILE_LINE, LOG_TRACE /*!< A verbose message useful for detailed debugging. */

#define LOG_alert(msg) LOG(FL_ALERT, msg) /*!< simple alert message */
#define LOG_err(msg) LOG(FL_ERR, msg)     /*!< simple error message */
#define LOG_warn(msg) LOG(FL_WARN, msg)   /*!< simple warning message */
#define LOG_info(msg) LOG(FL_INFO, msg)   /*!< simple information message */
#define LOG_debug(msg) LOG(FL_DEBUG, msg) /*!< simple debug message */
#define LOG_trace(msg) LOG(FL_TRACE, msg) /*!< simple trace message */

#endif /* SECUTILS_LOG_H_ */
