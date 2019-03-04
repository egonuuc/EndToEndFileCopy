// --------------------------------------------------------------
//
//                        fileclient.cpp
//
//        Author: Michael Egonu (megonu01) & Remmy Chen (rchen07)
//        Date: 02/10/2019     
//   
//        COMMAND LINE:
//        fileclient <server> <networknastiness> <filenastiness> <srcdir>
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
#include <math.h>
#include "utils.h"

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 

void checkArgs(int argc, char *argv[]);
void preprocessFiles(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *fileNames, queue<string> *fileContent, int network_nastiness);
int createPackets(string fileCon, vector<string> *packets);
void readFile(int nastiness, string filePath, queue<string> *fileContent);

const int serverArg = 1;     // server name is 1st arg

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
//                           main program
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

int main(int argc, char *argv[]) {
    ssize_t readlen;             // amount of data read from socket
    char incomingMessage[512];   // received message data
    string msgtxt;               // msgtxt to be sent
    bool timeout;                // T if packet was read, F if timeout occurred
    int network_nastiness, file_nastiness;
    DIR *SRC;
    vector<string> shaCodes;
    queue<string> fileNames;
    queue<string> fileContent;
    vector<string> packets; 
    int file_num = 0;
    int transmission_attempt = 0, end_to_end_attempt = 0, confirmation_attempt = 0;
    string pktList[] = {"SEND", "RECEIVED_ALL"};
    string msgList[] = {"BEGIN_TRANSMIT", "COMPLETED_TRANSMIT", "MATCHED_CHECKSUM", "WRONG_CHECKSUM", "ACKNOWLEDGEMENT", "REBEGIN"};
    int totalPacketNum = 0;


    GRADEME(argc, argv); // for grading
    checkArgs(argc, argv); // check command line arguments
    network_nastiness = atoi(argv[2]); // convert command line string to int
    file_nastiness = atoi(argv[3]); // convert command line string to int
    checkDirectory(argv[4]); // make sure source dir exists
    (void) network_nastiness; // TODO: to delete
    setUpDebugLogging("fileclientdebug.txt",argc, argv); // set up debug message logging

    SRC = opendir(argv[4]); // open source dir
    if (SRC == NULL) {
        fprintf(stderr,"Error opening source directory %s\n", argv[4]);
        exit(8);
    }
    preprocessFiles(argv[4], SRC, &shaCodes, &fileNames, &fileContent, file_nastiness);
    closedir(SRC);

    try { // Send / receive / print loop
        c150debug->printf(C150APPLICATION,"Creating C150DgmSocket"); // Create the socket
        C150DgmSocket *sock = new C150DgmSocket();
        sock -> setServerName(argv[serverArg]); // Tell the DGMSocket which server to talk to
        sock -> turnOnTimeouts(3000); // Allow time out if no packet is received for 3000 milliseconds

        while(!fileNames.empty()) {
            int nextFile = 0;

            // WRITE BEGIN_TRANSMIT:<fileName>:<totalPacketNum>
            string fileName = fileNames.front();
            string fileCon = fileContent.front();
            totalPacketNum = createPackets(fileCon, &packets);
            string initMsg = (msgList[0] + ":" + fileName + ":" + to_string(totalPacketNum)).c_str();
            if (nextFile++ == 0) {
                sock -> write(initMsg.c_str(), strlen(initMsg.c_str())+1);
                *GRADING << "File: " << fileName << ", beginning transmission, attempt "
                    << transmission_attempt << endl;
                cout << "File: " << fileName << ", beginning transmission, total packet number is " << totalPacketNum << endl;
            }

            int readAttempt = 0;
            int MAXATTEMPT = 5000;
            int requestedPacketNum = 0;
            int oneTimeOnly = 0;
            while(1) {
                if (oneTimeOnly++ == 0) {
                    sock -> write(packets[requestedPacketNum].c_str(), strlen(packets[requestedPacketNum].c_str())+1);
                }
                readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
                timeout = sock -> timedout();
                if (timeout == true && requestedPacketNum == 0) {
                    sock -> write(initMsg.c_str(), strlen(initMsg.c_str())+1);
                }
                if (timeout == true && ++readAttempt < MAXATTEMPT) { 
                    ++readAttempt;
                    sock -> write(packets[requestedPacketNum].c_str(), strlen(packets[requestedPacketNum].c_str())+1);
                    continue;
                }
                if (timeout == true && readAttempt >= MAXATTEMPT) { 
                    throw C150NetworkException("Server is down.");	
                }
                checkMsg(incomingMessage, readlen);

                string delimiter = ":";
                string s(incomingMessage);
                size_t pos = s.find(delimiter);
                string msg = s.substr(0, pos);
                if (strcmp(pktList[0].c_str(), msg.c_str()) == 0) {
                    s.erase(0, pos + delimiter.length());
                    pos = s.find(delimiter);
                    requestedPacketNum = atoi(s.substr(0, string::npos).c_str());
                    sock -> write(packets[requestedPacketNum].c_str(), strlen(packets[requestedPacketNum].c_str())+1);
                } else if (strcmp(incomingMessage, pktList[1].c_str()) == 0) {
                    oneTimeOnly = 0;
                    readAttempt = 0;
                    cout << "File: " << fileName << " transmission complete, "
                        << "waiting for end-to-end check, attempt "
                        << end_to_end_attempt << endl;
                    *GRADING << "File: " << fileName << " transmission complete, "
                        << "waiting for end-to-end check, attempt "
                        << end_to_end_attempt << endl;
                    break;
                }
            }

            // WRITE FILE HASH
            sock -> write(shaCodes[file_num].c_str(), strlen(shaCodes[file_num].c_str())+1); 

            // READ FILE HASH
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            timeout = sock -> timedout();
            if (timeout == true && ++end_to_end_attempt < MAXATTEMPT) { 
                ++end_to_end_attempt;
                ++transmission_attempt;
                sock -> write(shaCodes[file_num].c_str(), strlen(shaCodes[file_num].c_str())+1); 
                continue;
            } 
            if (timeout == true && end_to_end_attempt >= MAXATTEMPT) { 
                throw C150NetworkException("Server is down");	
            }
            checkMsg(incomingMessage, readlen);

            // If received file hash is correct, send MATCHED_CHECKSUM
            if (strcmp(incomingMessage, shaCodes[file_num].c_str()) == 0) {
                cout << "File: " << fileName << " file hash matched -- "
                    << "confirming with server" << endl;
                sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                end_to_end_attempt = 0;
                transmission_attempt = 0;
            } 
            // If received WRONG_CHECKSUM, retry file transmission
            else if (strcmp(incomingMessage, msgList[3].c_str()) == 0) {
                *GRADING << "File: " << fileName << " end-to-end check failed, "
                    << "attempt " << ++end_to_end_attempt << endl;
                if (end_to_end_attempt < MAXATTEMPT) {
                    cout << "File: " << fileName << " end-to-end check FAILS -- "
                        << "retrying" << endl;
                    ++transmission_attempt;
                    continue;
                }
                else { 
                    cout << "File: " << fileName << " end-to-end check FAILS -- "
                        << "giving up" << endl;
                    throw C150NetworkException("Something has gone wrong");	
                }
            }

            // read ACKNOWLEDGEMENT
            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
            if (timeout == true && ++confirmation_attempt < MAXATTEMPT) { 
                if (strcmp(incomingMessage, shaCodes[file_num].c_str()) == 0) {
                    cout << "File: " << fileName << " file hash matched -- "
                        << "confirming with server" << endl;
                    sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                    end_to_end_attempt = 0;
                    transmission_attempt = 0;
                } 
                ++confirmation_attempt;
                continue;
            }
            if (timeout == true && confirmation_attempt >= MAXATTEMPT) { 
                throw C150NetworkException("Server is down");	
            }
            checkMsg(incomingMessage, readlen);

            // If received ACKNOWLEDGEMENT
            if (strcmp(incomingMessage, msgList[4].c_str()) == 0) {
                cout << "File: " << fileName << ", acknowledgement received" << endl;
                *GRADING << "File: " << fileName << " end-to-end check succeeded, "
                    << "attempt " << confirmation_attempt << endl;
                if (strcmp(fileNames.front().c_str(), fileName.c_str()) == 0) {
                    ++file_num;
                    fileContent.pop();
                    fileNames.pop();
                    packets.clear();
                    confirmation_attempt = 0;
                    nextFile = 0;
                }
            }
            /*
            // If received anything else, resend confirmation
            else {
            if (++confirmation_attempt < MAXATTEMPT) {
            sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
            cout << "File: " << fileName << ", resending confirmation" << endl;
            }
            else 
            throw C150NetworkException("Something has gone wrong2");	
            }
            */
        }
        delete sock;
    }
    catch (C150NetworkException e) {
        c150debug->printf(C150ALWAYSLOG,"Caught C150NetworkException: %s\n",
                e.formattedExplanation().c_str());
        cerr << argv[0] << ": caught C150NetworkException: " << e.formattedExplanation() << endl;
    }
    return 0;
}

// ------------------------------------------------------
// //                   createPackets
// //
// //  Stores 5 chars representing packet number and 516 
// //  chars of file contents into packet, stores packet
// //  into a vector
// // ------------------------------------------------------
int createPackets(string fileCon, vector<string> *packets) {
    int packetno = 0;
    int offset = 0;
    size_t i;
    size_t fileSize = fileCon.length();
    size_t controlSize = 5;
    size_t count = 0;

    while ((size_t) offset < fileSize) {
        string control_str = to_string(packetno);
        while (control_str.size() < controlSize) {
            control_str = "0" + control_str;
        }
        char packet[512] = {'\0'};
        for (i = 0; i < controlSize; i++) {
            packet[i] = control_str[i];   
        }
        for (i = 0; i < 511 - controlSize; i++) {
            if (i + offset >= fileSize) {
                int ind = i + controlSize;
                packet[ind] = '\0';
                break;
            }
            packet[i + controlSize] = fileCon[i + offset];  
        }
        string p(packet);
        packets->push_back(p);
        packetno++;
        offset += (511 - controlSize);
        count++;
    }
    return packetno;
}

// ------------------------------------------------------
// //                   checkArgs
// //
// //  Validates the arguments from the command line
// // ------------------------------------------------------
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

// ------------------------------------------------------
// //                   readFile
// //
// //  Stores file content as a string
// // ------------------------------------------------------
void readFile(int nastiness, string filePath, queue<string> *fileContent){
    void *fopenretval;
    size_t len;
    string errorString;
    char *buffer;
    struct stat statbuf;  
    size_t sourceSize;

    try {
        if (lstat(filePath.c_str(), &statbuf) != 0) {
            exit(20);
        }

        sourceSize = statbuf.st_size;
        buffer = (char *)malloc(sourceSize+1);
        NASTYFILE inputFile(nastiness);    
        fopenretval = inputFile.fopen(filePath.c_str(), "rb");  

        if (fopenretval == NULL) {
            exit(12);
        }

        len = inputFile.fread(buffer, 1, sourceSize);
        if (len != sourceSize) {
            exit(16);
        }
        if (inputFile.fclose() != 0) {
            exit(16);
        }
        buffer[sourceSize] = '\0';
        string content(buffer);
        fileContent->push(content);
        free(buffer);
    }   catch (C150Exception e) {
        cerr << "nastyfiletest:copyfile(): Caught C150Exception: " << 
            e.formattedExplanation() << endl;
    }
}

// ------------------------------------------------------
// //                   preprocessFiles
// //
// //  Loops through files and stores SHA1 checksums and file names
// // ------------------------------------------------------
void preprocessFiles(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *fileNames, queue<string> *fileContent, int nastiness) {
    struct dirent *sourceFile;
    ifstream *t;
    stringstream *buffer;
    unsigned char obuf[20];

    while ((sourceFile = readdir(SRC)) != NULL) {
        // skip the . and .. names
        if ((strcmp(sourceFile->d_name, ".") == 0) ||
                (strcmp(sourceFile->d_name, "..")  == 0 )) 
            continue;

        string filePath = makeFileName(filepath, sourceFile->d_name);
        if (!isFile(filePath)) {
            continue;
        }

        t = new ifstream(filePath.c_str());
        buffer = new stringstream;
        *buffer << t->rdbuf();
        shaEncrypt(obuf, (const unsigned char *) buffer->str().c_str());
        //printFileHash(obuf, sourceFile->d_name);
        string str_obuf(reinterpret_cast<char*>(obuf),20);
        shaCodes->push_back(str_obuf);
        fileNames->push(sourceFile->d_name);

        delete t;
        delete buffer;

        readFile(nastiness, filePath, fileContent);
    }
}

