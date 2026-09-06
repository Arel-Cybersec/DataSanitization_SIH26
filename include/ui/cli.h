/**
 * @file cli.h
 * @brief Command-line interface declarations.
 */
#ifndef ERASECURE_CLI_H
#define ERASECURE_CLI_H

/**
 * @brief Parse arguments and dispatch CLI sub-commands.
 *
 * @param argc  Argument count from main().
 * @param argv  Argument vector from main().
 * @return      0 on success, non-zero on error.
 */
int cli_run(int argc, char *argv[]);

/**
 * @brief Print usage/help text to stdout.
 */
void cli_print_usage(void);

#endif /* ERASECURE_CLI_H */
