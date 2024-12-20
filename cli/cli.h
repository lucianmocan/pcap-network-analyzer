#ifndef CLI_H
#define CLI_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

void get_arguments(int argc, char** argv, char *interface, char *filename, char *filter, int *verbosity);

#endif