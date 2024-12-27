//
// Created by cryptic on 12/22/24.
//

/**
 * @file logger.h
 * @author Cryptiiiic
 * @brief This file is the header file for logger.c
 * @version 1.0.0
 * @date 2024-12-22
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_LOGGER_H
#define X8A4_LOGGER_H

/* Include headers */
#include <stdio.h>

/* Enum Variables */
enum LOG_LEVEL {
  LOG_INFO = 0,
  LOG_ERROR,
  LOG_DEBUG,
  LOG_DEBUG_ERROR,
};

/* Defines */
#define x8A4_log(format, ...) x8A4_logger(LOG_INFO, NULL, format, __VA_ARGS__)
#define x8A4_log_debug(format, ...) x8A4_logger(LOG_DEBUG, __FUNCTION__, format, __VA_ARGS__)
#define x8A4_log_error(format, ...) x8A4_logger(LOG_ERROR, __FUNCTION__, format, __VA_ARGS__)
#define x8A4_log_debug_error(format, ...) x8A4_logger(LOG_DEBUG_ERROR, __FUNCTION__, format, __VA_ARGS__)

/* Prototypes */
void x8A4_log_print(FILE *stream, const char *format, ...);
void x8A4_log_function(FILE *stream, const char *func, const char *format, va_list args);
void x8A4_logger(enum LOG_LEVEL level, const char *func, const char *format, ...);

#endif // X8A4_LOGGER_H