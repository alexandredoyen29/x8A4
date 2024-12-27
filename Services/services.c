//
// Created by cryptic on 4/14/24.
//

/**
 * @file services.c
 * @author Cryptiiiic
 * @brief This file is for all ioservice related code.
 * @version 1.0.0
 * @date 2024-04-14
 *
 * @copyright Copyright (c) 2024
 */

/* Include headers */
#include <stdio.h>
#include <x8A4/Registry/registry.h>
#include <x8A4/Services/services.h>

/* Cached Variables */
io_service_t io_aes_accel_service_cached = IO_OBJECT_NULL;
io_service_t apple_mobile_ap_nonce_service_cached = IO_OBJECT_NULL;
io_service_t apple_mobile_ap_nonce_service2_cached = IO_OBJECT_NULL;

/* Functions */
/**
 * @brief           Gets the IOAESAccelerator ioservice
 * @return          IOAESAccelerator ioservice
 */
io_service_t get_io_aes_accel_service(void) {
  if (io_aes_accel_service_cached != IO_OBJECT_NULL) {
    return io_aes_accel_service_cached;
  }
  io_service_t io_aes_accel_service = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching("IOAESAccelerator"));
  if (io_aes_accel_service == IO_OBJECT_NULL) {
    fprintf(stderr, "[-]: %s: Failed to find ioservice IOAESAccelerator!\n",
            __FUNCTION__);
  }
  io_aes_accel_service_cached = io_aes_accel_service;
  return io_aes_accel_service;
}

/**
 * @brief           Gets the AppleMobileApNonce ioservice
 * @return          AppleMobileApNonce ioservice
 */
io_connect_t get_apple_mobile_ap_nonce_service(void) {
  if (apple_mobile_ap_nonce_service2_cached != IO_OBJECT_NULL) {
    return apple_mobile_ap_nonce_service2_cached;
  }
  io_service_t apple_mobile_ap_nonce_service = IOServiceGetMatchingService(
      kIOMasterPortDefault, IOServiceMatching("AppleMobileApNonce"));
  if (apple_mobile_ap_nonce_service == IO_OBJECT_NULL) {
    fprintf(stderr, "[-]: %s: Failed to find ioservice AppleMobileApNonce!\n",
            __FUNCTION__);
  } else {
    apple_mobile_ap_nonce_service_cached = apple_mobile_ap_nonce_service;
  }
  io_connect_t apple_mobile_ap_nonce_service2 = IO_OBJECT_NULL;
  kern_return_t ret = IOServiceOpen(apple_mobile_ap_nonce_service, mach_task_self(), 0, &apple_mobile_ap_nonce_service2);
  if(ret == KERN_SUCCESS) {
    apple_mobile_ap_nonce_service2_cached = apple_mobile_ap_nonce_service2;
  } else {
    fprintf(stderr, "[-]: %s: Failed to open ioservice AppleMobileApNonce! (0x%X:%s)\n",
            __FUNCTION__, ret, mach_error_string(ret));
  }
  return apple_mobile_ap_nonce_service2;
}
