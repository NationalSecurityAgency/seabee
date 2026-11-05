// SPDX-License-Identifier: Apache-2.0
#ifndef CONSTANTS_H_
#define CONSTANTS_H_
/**
 * @file constants.h
 */

/**
 * @brief Copy of MODULE_PARAM_PREFIX_LEN in the kernel
 *
 * @see https://elixir.bootlin.com/linux/latest/source/include/linux/moduleparam.h#L21
 */
#define MODULE_NAME_LEN  (64 - sizeof(unsigned long))

/**
 * @brief Copy of PATH_MAX in the kernel
 *
 * @see https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/limits.h#L13
 */
#define PATH_MAX         4096

/// @brief maximum length of strings used for logging messages
#define MAX_STR_LEN      128

/// @brief the length of the name of an eBPF map
#define BPF_MAP_NAME_LEN 16

/// @brief the length of task comm string
#define COMM_LEN         16

// Indicates no policy ID
#define NO_POL_ID        0

// Indicates the base policy id
#define BASE_POLICY_ID   1

// Maximum number of policy ids on one object
#define MAX_POL_IDS      8

#endif
