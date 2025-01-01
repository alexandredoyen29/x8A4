//
// Created by cryptic on 4/14/24.
//

/**
 * @file slide.h
 * @author Cryptiiiic
 * @brief This file is the header file for slide.c
 * @version 1.0.1
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */
#ifndef X8A4_SLIDE_H
#define X8A4_SLIDE_H

/* Include headers */
#include <stdint.h>

/* Prototypes */
uint64_t get_slide(void);
uint64_t palera1n_get_slide(void);

/* Cached Variables */
extern uint64_t slide_cached;

#endif//X8A4_SLIDE_H
