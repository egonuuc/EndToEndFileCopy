// --------------------------------------------------------------
//
//                        fileserver.cpp
//
//        Author: Michael Egonu (megonu01) &  Remmy Chen (rchen07)
//        Date: 2/17/2019
//
//        COMMAND LINE
//
//              fileserver <networknastiness> <filenastiness> <targetdir>
//     
// --------------------------------------------------------------

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

using namespace C150NETWORK;  // for all the comp150 utilities 

void setUpDebugLogging(const char *logname, int argc, char *argv[]);
string makeFileName(string dir, string name);
void checkDirectory(char *dirname);
void shaEncrypt(unsigned char *hash, const unsigned char *message);
bool matchFileHash(char *filepath, DIR *TGT, C150DgmSocket *sock, char *incomingMessage);
void printFileHash(unsigned char *hash, char *file_name);
void checkArgs(int argc, char *argv[]);
void checkMsg(char (&incomingMessage)[512], ssize_t readlen);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//
//                           main program
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

int main(int argc, char *argv[]) {
    // Variable declarations
    char incomingMessage[512];   // received message data
    int network_nastiness;
    int file_nastiness;
    DIR *TGT;
    string file;
    string msgList[] = {"BEGIN_TRANSMIT", "COMPLETED_TRANSMIT", "MATCHED_CHECKSUM", "WRONG_CHECKSUM", "ACKNOWLEDGEMENT"};
    ssize_t readlen;
    bool matched;

    // DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    GRADEME(argc, argv);
    
    // Check command line arguments
    checkArgs(argc, argv);

    network_nastiness = atoi(argv[1]); // convert command line string to integer
    file_nastiness = atoi(argv[2]);    // convert command line string to integer
    
    (void) file_nastiness; // TODO : to delete

    //  Set up debug message logging. Added indents to server only, not
    //  client, so can merge logs and tell server and client entries apart
    //    cat fileserverdebug.txt fileserverclient.txt | sort
    setUpDebugLogging("fileserverdebug.txt",argc, argv);
    c150debug->setIndent("    ");              

    // Create socket, loop receiving and responding
    try {
        c150debug->printf(C150APPLICATION,"Creating C150NastyDgmSocket(nastiness=%d)",
                network_nastiness);
        C150DgmSocket *sock = new C150NastyDgmSocket(network_nastiness);
        c150debug->printf(C150APPLICATION,"Ready to accept messages");

        // infinite loop processing messages
        while(1) {
            
            // Read a packet. -1 in size below is to leave room for null
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1); // took out -1
            checkMsg(incomingMessage, readlen);

            // If received BEGIN_TRANSMIT:<filename>
            string delimiter = ":";
            string s(incomingMessage);
            size_t pos = s.find(delimiter);
            string initMsg = s.substr(0, pos);
            if (strcmp(msgList[0].c_str(), initMsg.c_str()) == 0) {
                file = s.substr(pos+1, string::npos);
                //printf("0 Transmission begins\n");
                *GRADING << "File: " << file << " starting to receive file" << endl;
            } 
            // If received COMPLETED_TRANSMIT
            else if (strcmp(msgList[1].c_str(), incomingMessage) == 0) {
                //printf("1 Transmission completed\n");
                *GRADING << "File: " << file << " received, beginning end-to-end check" << endl;
            } 
            // If received MATCHED_CHECKSUM
            else if (strcmp(msgList[2].c_str(),incomingMessage) == 0){
                //printf("4 Confirmed checksum\n");
                cout << "File: " << file << " copied successfully" << endl;
                sock -> write(msgList[4].c_str(), strlen(msgList[4].c_str())+1);
                *GRADING << "File: " << file << " end-to-end check succeeded" << endl;
            }
            // If received file hash (presumably)
            else { 
                TGT = opendir(argv[3]);
                if (TGT == NULL) {
                    fprintf(stderr,"Error opening target directory %s\n", argv[3]);
                    exit(8);
                }
                //printf("2 End to end begins\n");
                matched = matchFileHash(argv[3], TGT, sock, incomingMessage);
                if (matched == true) {
                    sock -> write(incomingMessage, strlen(incomingMessage)+1);
                } else {
                    //printf("3 Mismatched checksums\n");
                    string str = "WRONG_CHECKSUM";
                    //TODO If wrong checksum, delete temp file
                    sock -> write(str.c_str(), strlen(str.c_str())+1);
                    *GRADING << "File: " << file << " end-to-end check failed" << endl;
                }
                closedir(TGT);
            }
        }
    delete sock;
    }
    catch (C150NetworkException e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }
    return 4;
}

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

void checkArgs(int argc, char *argv[]) {
    // Check command line and parse arguments
    if (argc != 4) {
        fprintf(stderr,"Correct syntxt is: %s <networknastiness> "
                "<filenastiness> <targetdir>\n", argv[0]);
        exit(1);
    }
    if (strspn(argv[1], "0123456789") != strlen(argv[1])) {
        fprintf(stderr,"Network Nastiness %s is not numeric\n", argv[1]);     
        fprintf(stderr,"Correct syntxt is: %s <networknastiness_number>\n", 
                argv[0]);     
        exit(4);
    }

    if (strspn(argv[2], "0123456789") != strlen(argv[2])) {
        fprintf(stderr,"File Nastiness %s is not numeric\n", argv[2]);     
        fprintf(stderr,"Correct syntxt is: %s <filenastiness_number>\n", 
                argv[0]);     
        exit(4);
    }
}

bool matchFileHash(char *filepath, DIR *TGT, C150DgmSocket *sock, char *incomingMessage) {
    struct dirent *targetFile;
    ifstream *t;
    stringstream *buffer;
    unsigned char obuf[20];
    bool matched = false;
    string file;

    // loop through files
    while ((targetFile = readdir(TGT)) != NULL) {
        // skip the . and .. names
        if ((strcmp(targetFile->d_name, ".") == 0) ||
                (strcmp(targetFile->d_name, "..")  == 0 )) 
            continue;
            
        file = makeFileName(filepath, targetFile->d_name);
        t = new ifstream(file.c_str());
        buffer = new stringstream;
        *buffer << t->rdbuf();
        shaEncrypt(obuf, (const unsigned char *) buffer->str().c_str());
        string str_obuf(reinterpret_cast<char*>(obuf), 20);
        
        //printFileHash(obuf, targetFile->d_name);
        //string str_incoming(incomingMessage);
        //printFileHash((unsigned char *)str_incoming.c_str(), targetFile->d_name);   
        
        if (strcmp(incomingMessage, str_obuf.c_str()) == 0) {
            //printf("3 Matched checksums\n");
            delete t;
            delete buffer;
            matched = true;
            break;
        }
    }
    return matched;
}

void printFileHash(unsigned char *hash, char *file_name) {
    printf("SHA1 (\"%s\") = ", file_name);
    for (int i = 0; i < 20; i++) {
        printf("%02x", (unsigned int) hash[i]);
    }
    printf("\n");
}

void shaEncrypt(unsigned char *hash, const unsigned char *message) {
    string msg((const char *)message);
    SHA1(message, msg.length(), hash);
}

// ------------------------------------------------------
//                   makeFileName
                // open target dir
                // open target dir
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


// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//                     setUpDebugLogging
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

void setUpDebugLogging(const char *logname, int argc, char *argv[]) {
    //           Choose where debug output should go
    //
    // The default is that debug output goes to cerr.
    //
    // Uncomment the following three lines to direct
    // debug output to a file. Comment them to 
    // default to the console
    //  
    // Note: the new DebugStream and ofstream MUST live after we return
    // from setUpDebugLogging, so we have to allocate
    // them dynamically.
    //
    // Explanation: 
    // 
    //     The first line is ordinary C++ to open a file
    //     as an output stream.
    //
    //     The second line wraps that will all the services
    //     of a comp 150-IDS debug stream, and names that filestreamp.
    //
    //     The third line replaces the global variable c150debug
    //     and sets it to point to the new debugstream. Since c150debug
    //     is what all the c150 debug routines use to find the debug stream,
    //     you've now effectively overridden the default.
    ofstream *outstreamp = new ofstream(logname);
    DebugStream *filestreamp = new DebugStream(outstreamp);
    DebugStream::setDefaultLogger(filestreamp);

    //  Put the program name and a timestamp on each line of the debug log.
    c150debug->setPrefix(argv[0]);
    c150debug->enableTimestamp(); 

    // Ask to receive all classes of debug message
    //
    // See c150debug.h for other classes you can enable. To get more than
    // one class, you can or (|) the flags together and pass the combined
    // mask to c150debug -> enableLogging 
    //
    // By the way, the default is to disable all output except for
    // messages written with the C150ALWAYSLOG flag. Those are typically
    // used only for things like fatal errors. So, the default is
    // for the system to run quietly without producing debug output.
    c150debug->enableLogging(C150APPLICATION | C150NETWORKTRAFFIC | 
            C150NETWORKDELIVERY); 
}

