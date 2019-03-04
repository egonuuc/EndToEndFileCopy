
// --------------------------------------------------------------
//
//                        utils.h
//
//        Author: Michael Egonu (megonu01) &  Remmy Chen (rchen07)
//        Date: 2/17/2019
//
// --------------------------------------------------------------

#ifndef UTILS_H
#define UTILS_H

#include <cstdlib>
#include "c150debug.h"
#include <unistd.h>
#include <string>
#include <cstring>
#include <stdio.h>
#include <openssl/sha.h> 

void setUpDebugLogging(const char *logname, int argc, char *argv[]);
string makeFileName(string dir, string name);
void checkMsg(char (&incomingMessage)[512], ssize_t readlen);
void checkDirectory(char *dirname);
void printFileHash(unsigned char *hash, char *file_name);
bool isFile(string fname);
void shaEncrypt(unsigned char *hash, const unsigned char *message);

#endif
