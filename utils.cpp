
// --------------------------------------------------------------
//
//                        utils.cpp
//
//        Author: Michael Egonu (megonu01) &  Remmy Chen (rchen07)
//        Date: 2/17/2019
//
// --------------------------------------------------------------

#include "utils.h"
#include "c150nastydgmsocket.h"
#include <fstream>
#include <cstdlib>
#include "c150nastyfile.h"
#include "c150grading.h"
#include "c150dgmsocket.h"
#include "c150debug.h"
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdio.h>
#include <vector>
#include <openssl/sha.h> 

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//                     setUpDebugLogging
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
void setUpDebugLogging(const char *logname, int argc, char *argv[]) {
    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    //  Put the program name and a timestamp on each line of the debug log.
    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp(); 
    c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC | 
            C150NETWORKDELIVERY); 
}

// ------------------------------------------------------
//                   makeFileName
//
// Put together a directory and a file name, making
// sure there's a / in between
// ------------------------------------------------------
string makeFileName(string dir, string name) {
    stringstream ss;
    ss << dir;
    // make sure dir name ends in /
    if (dir.substr(dir.length()-1,1) != "/")
        ss << '/';
    ss << name;     // append file name to dir
    return ss.str();  // return dir/name
}

// ------------------------------------------------------
// //                   checkDirectory
// //
// //  Make sure directory exists
// // ------------------------------------------------------
void checkDirectory(char *dirname) {
    struct stat statbuf;
    if (lstat(dirname, &statbuf) != 0) {
        fprintf(stderr,"Error stating supplied source directory %s\n", dirname);
        exit(8);
    }

    if (!S_ISDIR(statbuf.st_mode)) {
        fprintf(stderr,"File %s exists but is not a directory\n", dirname);
        exit(8);
    }
}

// ------------------------------------------------------
// //                   checkMsg
// //
// //  Validates the incoming Message is a null terminated
// // string
// // ------------------------------------------------------
void checkMsg(char (&incomingMessage)[512], ssize_t readlen) {
    if (readlen == 0) {
        return;
    }
    incomingMessage[readlen] = '\0'; // make sure null terminated
    if (readlen > (int)sizeof(incomingMessage)) {
        throw C150NetworkException("Unexpected over length read in server");
    }
    if (incomingMessage[readlen] != '\0') {
        throw C150NetworkException("Server received message that was not null terminated");
    }
}


// ------------------------------------------------------
//                   isFile
//
//  Make sure the supplied file is not a directory or
//  other non-regular file.
// ------------------------------------------------------
bool isFile(string fname) {
    const char *filename = fname.c_str();
    struct stat statbuf;  
    if (lstat(filename, &statbuf) != 0) {
        fprintf(stderr,"isFile: Error stating supplied source file %s\n", filename);
        return false;
    }

    if (!S_ISREG(statbuf.st_mode)) {
        fprintf(stderr,"isFile: %s exists but is not a regular file\n", filename);
        return false;
    }
    return true;
}

// ------------------------------------------------------
// //                   printFileHash
// //
// //  Prints the passed in SHA1 hash in a readable format
// // ------------------------------------------------------
void printFileHash(unsigned char *hash, char *file_name) {
    printf("SHA1 (\"%s\") = ", file_name);
    for (int i = 0; i < 20; i++) {
        printf("%02x", (unsigned int) hash[i]);
    }
    printf("\n");
}

// ------------------------------------------------------
// //                   shaEncrypt
// //
// //  Makes a SHA1 hash of the message provided
// // ------------------------------------------------------
void shaEncrypt(unsigned char *hash, const unsigned char *message) {
    string msg((const char *)message);
    SHA1(message, msg.length(), hash);
}



