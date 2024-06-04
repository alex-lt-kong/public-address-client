#define _GNU_SOURCE // Without this, VSCode keeps complaining that sigaction is
                    // an "incomplete type"

#include "http_service.h"
#include "queue.h"
#include "utils.h"

#include <json-c/json.h> /* JSON */
#include <microhttpd.h>

#include <dirent.h> /* Check directory's existence*/
#include <errno.h>
#include <getopt.h>
#include <linux/limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

volatile sig_atomic_t e_flag = 0;

static void signal_handler(int signum) {
  char msg[] = "Signal [  ] caught, exiting\n";
  msg[8] = '0' + (char)(signum / 10);
  msg[9] = '0' + (char)(signum % 10);
  write(STDIN_FILENO, msg, strlen(msg));
  e_flag = 1;
}

int install_signal_handler() {
  // This design canNOT handle more than 99 signal types
  if (_NSIG > 99) {
    syslog(LOG_ERR, "signal_handler() can't handle more than 99 signals");
    return -1;
  }
  struct sigaction act;
  // Initialize the signal set to empty, similar to memset(0)
  if (sigemptyset(&act.sa_mask) == -1) {
    syslog(LOG_ERR, "sigemptyset()");
    return -2;
  }
  act.sa_handler = signal_handler;
  /* SA_RESETHAND means we want our signal_handler() to intercept the signal
  once. If a signal is sent twice, the default signal handler will be used
  again. `man sigaction` describes more possible sa_flags. */
  act.sa_flags = SA_RESETHAND;
  // act.sa_flags = 0;
  if (sigaction(SIGINT, &act, 0) == -1 || sigaction(SIGTERM, &act, 0) == -1) {
    syslog(LOG_ERR, "sigaction()");
    return -3;
  }
  return 0;
}

void print_usage(const char *binary_name) {

  printf("Usage: %s [OPTION]\n\n", binary_name);

  printf("Options:\n"
         "  --help,        -h        Display this help and exit\n"
         "  --config-path, -c        Path of JSON format configuration file\n");
}

const char *parse_args(int argc, char *argv[]) {
  static struct option long_options[] = {
      {"config-path", required_argument, 0, 'c'},
      {"help", optional_argument, 0, 'h'},
      {0, 0, 0, 0}};
  int opt, option_idx = 0;
  while ((opt = getopt_long(argc, argv, "c:h", long_options, &option_idx)) !=
         -1) {
    switch (opt) {
    case 'c':
      // optarg it is a pointer into the original argv array
      return optarg;
    }
  }
  print_usage(argv[0]);
  _exit(1);
}
int main(int argc, char **argv) {
  int retval = 0;
  const char *config_path = parse_args(argc, argv);

  (void)openlog(PROGRAM_NAME, LOG_PID | LOG_CONS, 0);

  if (install_signal_handler() < 0) {
    retval = -1;
    goto err_install_sighandler;
  }

  if (load_values_from_json(config_path) < 0) {
    retval = -1;
    syslog(LOG_ERR, "Invalid configuration");
    goto err_invalid_config;
  }

  if (pacq_initialize_queue() < 0) {
    retval = -1;
    goto err_init_queue;
  }
  struct MHD_Daemon *d = init_mhd();
  if (d == NULL) {
    retval = -1;
    goto err_init_mhd;
  }
  syslog(LOG_INFO, "initialized");

  // getc() won't work without an interactive shell.
  // (void)getc(stdin);
  while (e_flag == 0) {
    sleep(1);
  }
  syslog(LOG_INFO, "exiting");
  MHD_stop_daemon(d);
err_init_mhd:
  pacq_finalize_queue();
err_init_queue:
err_invalid_config:
err_install_sighandler:
  closelog();
  return retval;
}
