#ifndef CLI_HELPER_H
#define CLI_HELPER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "interface.h"

#include <pcap.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define CMD_ARG_SIZE 100

void display_welcome_message();
void display_help();
void display_interfaces();

void get_arguments(int argc, char** argv, char *interface, char *filename, char *filter, int *verbosity);
int check_interface(char* interface);
int check_file(char* filename);
int check_filter(char* filter);
void check_all(char* interface, char* filename, char* filter, int verbosity);

#endif