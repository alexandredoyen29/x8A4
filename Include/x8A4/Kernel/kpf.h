//
// Created by cryptic on 4/27/24.
//

/**
 * @file kpf.h
 * @author Cryptiiiic
 * @brief This file is the header file for kpf.c
 * @version 1.0.1
 * @date 2024-04-27
 *
 * @copyright Copyright (c) 2024
 */

#ifndef X8A4_KPF_H
#define X8A4_KPF_H

/* Include Headers */
#include <stdint.h>
#include <XPF/xpf.h>

/* External prototypes */
extern PFSection *xpf_pfsec_init(const char *filesetEntryId, const char *segName, const char *sectName);

/* Prototypes */
int xpf_setup_fileset_sections(void);
void xpf_free_fileset_sections(void);
uint64_t xpf_find_nonce_slots_array(void);
uint64_t xpf_find_nonce_domains_array(void);
int xpf_find_nonce_slots_array_length(void);
int xpf_find_nonce_domains_array_length(uint64_t nonce_domains_array_addr);
int xpf_find_cryptex_boot_domain_index(uint64_t nonce_domains_array_addr, int nonce_domains_array_length);

/* Extern Variables */
extern PFSection *apple_image4_fileset_sections[3];

/* Cached Variables */
extern uint64_t kpf_nonce_domains_cached;
extern int kpf_nonce_domains_length_cached;

#endif // X8A4_KPF_H
