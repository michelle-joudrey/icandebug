#pragma once

extern char *optarg;
extern int optind;
int getopt(int argc, char *const argv[], const char *optstring);