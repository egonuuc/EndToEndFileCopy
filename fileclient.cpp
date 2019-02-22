// --------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Author: Michael Egonu (megonu01) & Remmy Chen (rchen07)
//        Date: 02/10/2019     
//   
//        COMMAND LINE
//
//              fileclient <server> <networknastiness> <filenastiness> <srcdir>
//
// --------------------------------------------------------------

#include "c150nastyfile.h"
#include "c150grading.h"
#include "c150dgmsocket.h"
#include "c150debug.h"
#include <fstream>
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
#include <queue>
#include <openssl/sha.h>
#include <cstdlib>

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 

// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
string makeFileName(string dir, string name);
void checkDirectory(char *dirname);
void shaEncrypt(unsigned char *hash, const unsigned char *message);
void encryptFileNames(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *files);
void printFileHash(unsigned char *hash, char *file_name);
void checkArgs(int argc, char *argv[]);
void checkMsg(char (&incomingMessage)[512], ssize_t readlen);

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//                    Command line arguments
//
// The following are used as subscripts to argv, the command line arguments
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

const int serverArg = 1;     // server name is 1st arg

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//                           main program
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

int main(int argc, char *argv[]) {
    // Variable declarations
    ssize_t readlen;             // amount of data read from socket
    char incomingMessage[512];   // received message data
    string msgtxt;               // msgtxt to be sent
    bool timeout;                // T if packet was read, F if timeout occurred
    int network_nastiness, file_nastiness;
    DIR *SRC;
    vector<string> shaCodes;
    queue<string> files;
    int file_num = 0;
    int transmission_attempt = 0, end_to_end_attempt = 0, confirmation_attempt = 0;
    string msgList[] = {"BEGIN_TRANSMIT", "COMPLETED_TRANSMIT", "MATCHED_CHECKSUM", "WRONG_CHECKSUM", "ACKNOWLEDGEMENT"};

    // DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    GRADEME(argc, argv);
    
    // Check command line arguments
    checkArgs(argc, argv);
    network_nastiness = atoi(argv[2]); // convert command line string to int
    file_nastiness = atoi(argv[3]); // convert command line string to int
    checkDirectory(argv[4]); // make sure source dir exists
    
    (void) network_nastiness; // TODO: to delete
    (void) file_nastiness; // TODO : to delete

    // Set up debug message logging
    setUpDebugLogging("fileclientdebug.txt",argc, argv);

    // open source dir
    SRC = opendir(argv[4]);
    if (SRC == NULL) {
        fprintf(stderr,"Error opening source directory %s\n", argv[4]);
        exit(8);
    }
    encryptFileNames(argv[4], SRC, &shaCodes, &files);
    closedir(SRC);

    // Send / receive / print loop
    try {
        // Create the socket
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket");
        C150DgmSocket *sock = new C150DgmSocket();

        // Tell the DGMSocket which server to talk to
        sock -> setServerName(argv[serverArg]);  

        // Allow time out if no packet is received for 3000 milliseconds
        sock -> turnOnTimeouts(3000);

        while(!files.empty()) {

            // WRITE BEGIN_TRANSMIT:<filename>
            string file = files.front();
            //printf("0 File to transmit is %s\n", file.c_str());
            string initMsg = (msgList[0] + ":" + file).c_str();
            sock -> write(initMsg.c_str(), strlen(initMsg.c_str())+1);
            *GRADING << "File: " << file << ", beginning transmission, attempt "
                << transmission_attempt << endl;

            // TODO - TRANSMIT FILES

            // WRITE COMPLETED_TRANSMIT
            sock -> write(msgList[1].c_str(), strlen(msgList[1].c_str())+1); 
            *GRADING << "File: " << file << " transmission complete, waiting "
                << "for end-to-end check, attempt " << end_to_end_attempt 
                << endl;

            // WRITE FILE HASH
            sock -> write(shaCodes[file_num].c_str(), strlen(shaCodes[file_num].c_str())+1); 
            //printFileHash((unsigned char *)shaCodes[file_num].c_str(), (char *)file.c_str());

            // READ FILE HASH
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            checkMsg(incomingMessage, readlen);
            // Determine if timeout has occurred (T) or if packet was read (F)
            timeout = sock -> timedout();

            // If a timeout has occurred, retry file transmission
            // (after 5 tries, throws a C150NetworkException)
            if (timeout == true && ++end_to_end_attempt < 5) { 
                //printf("time out\n");
                ++end_to_end_attempt;
                ++transmission_attempt;
                continue;
            } 
            if (timeout == true && end_to_end_attempt >= 5) { 
                throw C150NetworkException("Sever is down");	
            }

            // If received file hash is correct, send confirmation
            if (strcmp(incomingMessage, shaCodes[file_num].c_str()) == 0) {
                //printf("1 Correct checksum\n");
                cout << "File: " << file << " end-to-end check SUCCEEDED -- "
                    << "informing server" << endl;
                sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                end_to_end_attempt = 0;
                transmission_attempt = 0;
            } 
            // If received WRONG_CHECKSUM, retry file transmission
            else if (strcmp(incomingMessage, msgList[3].c_str()) == 0) {
                *GRADING << "File: " << file << " end-to-end check failed, "
                    << "attempt " << ++end_to_end_attempt << endl;
                if (end_to_end_attempt < 5) {
                    cout << "File: " << file << " end-to-end check FAILS -- "
                        << "retrying" << endl;
                    ++transmission_attempt;
                    continue;
                }
                else { 
                    cout << "File: " << file << " end-to-end check FAILS -- "
                        << "giving up" << endl;
                    throw C150NetworkException("Something has gone wrong");	
                }
            }

            // READ ACKNOWLEDGEMENT
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            checkMsg(incomingMessage, readlen);
            // Determine if timeout has occurred (T) or if packet was read (F)
            timeout = sock -> timedout();

            // If a timeout has occurred, resend confirmation to the server 
            // (after 5 tries, throws a C150NetworkException)
            if (timeout == true && ++confirmation_attempt < 5) { 
                sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                ++confirmation_attempt;
                continue;
            }
            if (timeout == true && confirmation_attempt >= 5) { 
                throw C150NetworkException("Sever is down");	
            }

            // If received ACKNOWLEDGEMENT
            if (strcmp(incomingMessage, msgList[4].c_str()) == 0) {
                //printf("2 Acknowledgement received\n");
                *GRADING << "File: " << file << " end-to-end check succeeded, "
                    << "attempt " << confirmation_attempt << endl;
                files.pop();
                ++file_num;
                confirmation_attempt = 0;
            }
            // If received anything else, resend confirmation
            else {
                printf("2 Something has gone wrong\n");
                //printFileHash((unsigned char *)incomingMessage, (char *)file.c_str());
                //printFileHash((unsigned char *)shaCodes[file_num].c_str(), (char *)file.c_str());
                //checkAndPrintMessage(readlen, incomingMessage, sizeof(incomingMessage));
                if (++confirmation_attempt < 5)
                    sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                else 
                    throw C150NetworkException("Something has gone wrong2");	
            }
        }
    delete sock;
    }
    //  Handle networking errors -- for now, just print message and give up!
    catch (C150NetworkException e) {
        // Write to debug log
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                e.formattedExplanation().c_str());
        // In case we're logging to a file, write to the console too
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }
    return 0;
}


void checkMsg(char (&incomingMessage)[512], ssize_t readlen) {
    if (readlen == 0) {
        return;
    }
    incomingMessage[readlen] = '\0'; // make sure null terminated 
    if (readlen > (int)sizeof(incomingMessage)) {
        throw C150NetworkException("Unexpected over length read in client");
    }
    if(incomingMessage[readlen] != '\0') {
        throw C150NetworkException("Client received message that was not null terminated");	
    };
}

void checkArgs(int argc, char *argv[]) {
    // Check command line
    if (argc != 5) {
        fprintf(stderr, 
                "Correct syntxt is: %s <server> <networknastiness> "
                "<filenastiness> <srcdir>\n",argv[0]);
        exit(1);
    }

    if (strspn(argv[2], "0123456789") != strlen(argv[2])) {
        fprintf(stderr,"Network nastiness %s is not numeric\n", argv[2]);
        fprintf(stderr,"Correct syntxt is: %s <networknastiness_number>\n", 
                argv[0]);     
        exit(4);
    }

    if (strspn(argv[3], "0123456789") != strlen(argv[3])) {
        fprintf(stderr,"File nastiness %s is not numeric\n", argv[3]);
        fprintf(stderr,"Correct syntxt is: %s <filenastiness_number>\n", 
                argv[0]);     
        exit(4);
    }
}

void encryptFileNames(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *files) {
    struct dirent *sourceFile;
    ifstream *t;
    stringstream *buffer;
    unsigned char obuf[20];


    // loop through files, printing checksums
    while ((sourceFile = readdir(SRC)) != NULL) {
        // skip the . and .. names
        if ((strcmp(sourceFile->d_name, ".") == 0) ||
                (strcmp(sourceFile->d_name, "..")  == 0 )) 
            continue;

        string filePath = makeFileName(filepath, sourceFile->d_name);
        t = new ifstream(filePath.c_str());
        buffer = new stringstream;
        *buffer << t->rdbuf();
        shaEncrypt(obuf, (const unsigned char *) buffer->str().c_str());
        //printFileHash(obuf, sourceFile->d_name);
        string str_obuf(reinterpret_cast<char*>(obuf),20);
        shaCodes->push_back(str_obuf);
        files->push(sourceFile->d_name);
        delete t;
        delete buffer;
    }
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
//                     checkAndPrintMessage
//
//        Make sure length is OK, clean up response buffer
//        and print it to standard output.
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

void checkAndPrintMessage(ssize_t readlen, char *msg, ssize_t bufferlen) {
    // Except in case of timeouts, we're not expecting a zero length read
    if (readlen == 0) {
        throw C150NetworkException("Unexpected zero length read in client");
    }

    // DEFENSIVE PROGRAMMING: we aren't even trying to read this much
    // We're just being extra careful to check this
    if (readlen > (int)(bufferlen)) {
        throw C150NetworkException("Unexpected over length read in client");
    }

    // Make sure server followed the rules and sent a null-terminated string 
    // (well, we could check that it's all legal characters, but at least we 
    // look for the null)
    if(msg[readlen-1] != '\0') {
        throw C150NetworkException("Client received message that was not null terminated");	
    };

    // Echo the response on the console
    string s(msg);
    cleanString(s);

    c150debug->printf(C150APPLICATION,"PRINTING RESPONSE: Response received is \"%s\"",
            s.c_str());

    printf("Response received is \"%s\"\n", s.c_str());
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
    // debug output to a file. Comment them
    // to default to the console.
    //
    // Note: the new DebugStream and ofstream MUST live after we return
    // from setUpDebugLogging, so we have to allocate
    // them dynamically.
    //
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
