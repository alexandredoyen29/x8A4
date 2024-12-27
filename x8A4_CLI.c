//
// Created by cryptic on 4/14/24.
//

/* Include headers */
#include <x8A4/x8A4.h>
#include <x8A4/Logger/logger.h>
#include <getopt.h>

/* Structure Variables */
static struct option x8A4_options[] = {
    {"help", 0, NULL, 'h'},
    {"verbose", 0, NULL, 'v'},
    {"print-all", 0, NULL, 'a'},
    {"get-cryptex-seed", 0, NULL, 'x'},
    {"get-cryptex-nonce", 0, NULL, 't'},
    {"get-apnonce-generator", 0, NULL, 'g'},
    {"get-apnonce", 0, NULL, 'n'},
    {"set-apnonce-generator", required_argument, NULL, 's'},
    {"clear-apnonce-generator", 0, NULL, 'c'},
    {"get-accel-key", required_argument, NULL, 'k'},
    {"get-accel-keys", 0, NULL, 'l'},
    {"get-nonce-seeds", 0, NULL, 'd'},
    {"set-cryptex-nonce", required_argument, NULL, 'z'},
    {NULL, 0, NULL, 0}
};

/* Functions */
/**
 * @brief           CLI print program help
 */
void x8A4_help(const char *cmd) {
  char *command = (char *)cmd;
  if(!command) {
    command = "x8A4";
  }
  x8A4_log("%s: An all-in-one tool for firmware nonces, seeds, and downgrade support\n", x8A4_version());
  x8A4_log("Usage: %s [OPTIONS]\n", command);
  x8A4_log("\n%sOptions:\n", "");
  x8A4_log("  %s, %s\t\t\t\t\t\t%s\n", "-h", "--help", "Shows this help message");
  x8A4_log("  %s, %s\t\t\t\t\t\t%s\n", "-v", "--verbose", "Enables this tool's verbose mode");
  x8A4_log("  %s, %s\t\t\t\t\t%s\n", "-a", "--print-all", "Dumps and prints everything :)");
  x8A4_log("\n%sOptions:\n", "Cryptex ");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-x", "--get-cryptex-seed", "Gets the current Cryptex1 boot seed from nvram");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-t", "--get-cryptex-nonce", "Calculates the current Cryptex1 boot nonce");
  x8A4_log("\n%sOptions:\n", "APNonce ");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-g", "--get-apnonce-generator", "Gets the current APNonce generator from nvram");
  x8A4_log("  %s, %s\t\t\t\t\t%s\n", "-n", "--get-apnonce", "Calculates the current APNonce");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-s", "--set-apnonce-generator", "Set a specified APNonce generator in nvram");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-c", "--clear-apnonce-generator", "Clears the current APNonce generator from nvram");
  x8A4_log("\n%sOptions:\n", "Encryption Key ");
  x8A4_log("  %s, %s\t\t\t\t\t%s\n", "-k", "--get-accel-key", "Gets a specified IOAESAccelerator encryption key from kernel via its ID");
  x8A4_log("  %s, %s\t\t\t\t\t%s\n", "-l", "--get-accel-keys", "Dumps all of the IOAESAccelerator encryption keys from kernel");
  x8A4_log("\n%sOptions:\n", "Seed ");
  x8A4_log("  %s, %s\t\t\t\t\t%s\n", "-d", "--get-nonce-seeds", "Dumps all of the nonce seeds domains/nonce slots from nvram");
  x8A4_log("\n%sOptions:\n", "Secret Menu ");
  x8A4_log("  %s, %s\t\t\t\t%s\n", "-z", "--set-cryptex-nonce", "Sets a specified Cryptex1 boot seed in nvram(DANGEROUS: BOOTLOOP!)");
}

/**
 * @brief           CLI set program verbose
 */
void set_verbose() {
  x8A4_cli_set_verbose();
}

/**
 * @brief           CLI call all program getters
 */
void print_all() {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_cryptex_seed();
  x8A4_cli_get_cryptex_nonce();
  x8A4_cli_get_apnonce_generator();
  x8A4_cli_get_apnonce();
  x8A4_cli_get_accel_keys(0);
  x8A4_cli_get_nonce_seeds();
}

/**
 * @brief           CLI get cryptex seed
 */
void get_cryptex_seed(void) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_cryptex_seed();
}

/**
 * @brief           CLI get cryptex nonce
 */
void get_cryptex_nonce(void) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_cryptex_nonce();
}

/**
 * @brief           CLI get apnonce generator
 */
void get_apnonce_generator(void) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_apnonce_generator();
}

/**
 * @brief           CLI get apnonce
 */
void get_apnonce(void) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_apnonce();
}

/**
 * @brief           CLI set apnonce generator
 * @param[in]       new_generator
 */
void set_apnonce_generator(const char *new_generator) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_set_apnonce_generator(new_generator);
}

/**
 * @brief           CLI clear apnonce generator
 */
void clear_apnonce_generator() {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_clear_apnonce_generator();
}

/**
 * @brief           CLI get IOAESAccelerator keys
 * @param[in]       chosen_key
 */
void get_accel_keys(uint32_t chosen_key) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_accel_keys(chosen_key);
}

void get_nonce_seeds(void) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_get_nonce_seeds();
}

/**
 * @brief           CLI set cryptex seed
 * @param[in]       new_seed
 */
void set_cryptex_seed(const char *new_seed) {
  if(x8A4_init()) {
    return;
  }
  x8A4_cli_set_cryptex_seed(new_seed);
}

/**
 * @brief           CLI main
 * @param[in]       argc
 * @param[in]       argv
 */
int main(int argc, char **argv) {
  int x8A4_opt = 0;
  int x8A4_opt_index = 0;
  while((x8A4_opt = getopt_long(argc, (char* const *)argv, "hvaxtgns:ck:ldz:", x8A4_options, &x8A4_opt_index)) > 0) {
    switch(x8A4_opt) {
      case 'h':
        x8A4_help(argv[0]);
        break;
      case 'v':
        set_verbose();
        break;
      case 'a':
        print_all();
        break;
      case 'x':
        get_cryptex_seed();
        break;
      case 't':
        get_cryptex_nonce();
        break;
      case 'g':
        get_apnonce_generator();
        break;
      case 'n':
        get_apnonce();
        break;
      case 's':
        if(optarg) {
          set_apnonce_generator(optarg);
        }
        break;
      case 'c':
        clear_apnonce_generator();
        break;
      case 'k':
        if(optarg) {
          get_accel_keys(strtoul(optarg, NULL, 0));
        }
        break;
      case 'l':
        get_accel_keys(0);
        break;
      case 'd':
        get_nonce_seeds();
        break;
      case 'z':
        if(optarg) {
          set_cryptex_seed(optarg);
        }
        break;
      default:
        x8A4_help(argv[0]);
        return -1;
    }
  }
  if(argc == 1) {
    x8A4_help(argv[0]);
  }
  return 0;
}
