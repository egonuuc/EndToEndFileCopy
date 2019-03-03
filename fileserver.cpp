// --------------------------------------------------------------
//
//                        fileserver.cpp
//
//        Author: Michael Egonu (megonu01) &  Remmy Chen (rchen07)
//        Date: 2/17/2019
//
//        COMMAND LINE
//
//        fileserver <networknastiness> <filenastiness> <targetdir>
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
bool matchFileHash(char *filepath, DIR *TGT, char *incomingMessage);
void printFileHash(unsigned char *hash, char *file_name);
void checkArgs(int argc, char *argv[]);
void checkMsg(char (&incomingMessage)[512], ssize_t readlen);
bool isFile(string fname);
void writeFile(int nastiness, char *targetDir, string fileName, vector<string> *fileContent);
void storePacket(char *incomingMessage, vector<string> *fileContent, int control_index, int *packetTracker);
void extractControlInfo(char *incomingMessage, int *control_index);
void cleanBadFiles(char *filepath, DIR *TGT);

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
    string pktList[] = {"SEND", "RECEIVED_ALL"};
    string msgList[] = {"BEGIN_TRANSMIT", "COMPLETED_TRANSMIT", "MATCHED_CHECKSUM", "WRONG_CHECKSUM", "ACKNOWLEDGEMENT", "REBEGIN"};
    ssize_t readlen;
    bool matched;
    vector<string> fileContent; //(1000);
    int totalPacketNum;
    bool timeout;
    
    // DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    GRADEME(argc, argv);
    
    // Check command line arguments
    checkArgs(argc, argv);

    network_nastiness = atoi(argv[1]); // convert command line string to integer
    file_nastiness = atoi(argv[2]);    // convert command line string to integer
    
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

        // Allow time out if no packet is received for 3000 milliseconds
        sock -> turnOnTimeouts(3000);

        // infinite loop processing messages
        while(1) {

            readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1); // took out -1
            timeout = sock -> timedout();
            if (timeout == true) {
                continue;
            }
            checkMsg(incomingMessage, readlen);

            // If received BEGIN_TRANSMIT:<fileName>:<totalPacketNum>
            string delimiter = ":";
            string s(incomingMessage);
            size_t pos = s.find(delimiter);
            string initMsg = s.substr(0, pos);
            if (strcmp(msgList[0].c_str(), initMsg.c_str()) == 0) {
                s.erase(0, pos + delimiter.length());
                pos = s.find(delimiter);
                file = s.substr(0, pos);
                s.erase(0, pos + delimiter.length());
                totalPacketNum = atoi(s.substr(0, string::npos).c_str());
                int *packetTracker = new int[totalPacketNum];
                memset(packetTracker, 0, totalPacketNum*sizeof(int));
                *GRADING << "File: " << file << " starting to receive file" << endl;
                
                int readAttempt = 0;
                int MAXATTEMPT = 5000;
                int control_index = 0;
                while(1) {
                    readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
                    timeout = sock -> timedout();
                    if (timeout == true && ++readAttempt < MAXATTEMPT) { 
                        ++readAttempt;
                        continue;
                    }
                    if (timeout == true && readAttempt >= MAXATTEMPT) { 
                        throw C150NetworkException("Server is down");	
                    }
                    
                    checkMsg(incomingMessage, readlen);
                    if (strspn(incomingMessage, "0123456789") < 5) {
                        ++readAttempt;
                        continue;
                    }
                    extractControlInfo(incomingMessage, &control_index);
                    if (fileContent.size() < (unsigned int)totalPacketNum) {
                        if (packetTracker[control_index] == 0) {
                            storePacket(incomingMessage, &fileContent, control_index, packetTracker);
                            if (fileContent.size() < (unsigned int)totalPacketNum) {
                                string sendRequest = pktList[0] + ':' + to_string(control_index + 1);
                                sock->write(sendRequest.c_str(), strlen(sendRequest.c_str())+1);
                            }
                        }
                    } 
                    if (fileContent.size() == (unsigned int)totalPacketNum) {
                        sock->write(pktList[1].c_str(), strlen(pktList[1].c_str())+1);
                        writeFile(file_nastiness, argv[3], file, &fileContent);
                        readAttempt = 0;
                        break;
                    }
                }
            }
            // If received MATCHED_CHECKSUM
            else if (strcmp(msgList[2].c_str(),incomingMessage) == 0){
                cout << "File: " << file << " copied successfully" << endl;
                sock -> write(msgList[4].c_str(), strlen(msgList[4].c_str())+1);
                *GRADING << "File: " << file << " end-to-end check succeeded" << endl;
                string targetName = makeFileName(argv[3], file + ".TMP");
                string newName = makeFileName(argv[3], file);
                rename(targetName.c_str(), newName.c_str());
                TGT = opendir(argv[3]);
                if (TGT == NULL) {
                    fprintf(stderr,"Error opening target directory %s\n", argv[3]);
                    exit(8);
                }
                cleanBadFiles(argv[3], TGT);
                closedir(TGT);
                fileContent.clear();
                initMsg = "";
                continue;
            }
            // If received file hash (presumably)
            else { 
                if (strspn(incomingMessage, "0123456789") == 5) {
                    continue;
                }
                TGT = opendir(argv[3]);
                if (TGT == NULL) {
                    fprintf(stderr,"Error opening target directory %s\n", argv[3]);
                    exit(8);
                }
                matched = matchFileHash(argv[3], TGT, incomingMessage);
                if (matched == true) {
                    sock -> write(incomingMessage, strlen(incomingMessage)+1);
                } else {
                    string str = "WRONG_CHECKSUM";
                    sock -> write(str.c_str(), strlen(str.c_str())+1);
                    cout << "File: " << file << " end-to-end check failed" << endl;
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

void cleanBadFiles(char *filepath, DIR *TGT) {
    struct dirent *targetFile;
    // loop through files
    while ((targetFile = readdir(TGT)) != NULL) {
        // skip the . and .. names
        if ((strcmp(targetFile->d_name, ".") == 0) ||
                (strcmp(targetFile->d_name, "..")  == 0 )) 
            continue;
        string tFile(targetFile->d_name);
        cout << (tFile.substr(tFile.length() - 4, 4)) << endl;
        if (strcmp(".TMP", (tFile.substr(tFile.length() - 4, 4)).c_str()) == 0) {
            remove(targetFile->d_name);
        }
    }
}


// ------------------------------------------------------
// //                  extractControlInfo
// //
// //  Strips out the contol information from the package
// //  and uses that to assign a correct packet number
// // ------------------------------------------------------
void extractControlInfo(char *incomingMessage, int *control_index) {
    string control_str = "";
    for (int i = 0; i < 5; i++) {
        control_str += incomingMessage[i];   
    }
    while (control_str.length() > 1) {
        if (control_str[0] != '0')
            break;
        control_str.erase(0, 1);
    }
    *control_index = atoi(control_str.c_str());
}

// ------------------------------------------------------
// //                   storePacket
// //
// //  Stores the packet in its correct spot in
// //  the file content structure
// // ------------------------------------------------------
void storePacket(char *incomingMessage, vector<string> *fileContent, int control_index, int *packetTracker) {
    vector<string>::iterator index;
    string fileCon = "";
    for (int i = 5; i < 512; i++) {
        if (incomingMessage[i] == '\0')
            break;
        fileCon += incomingMessage[i];
    }
    index = (fileContent->begin() + control_index);
    fileContent->insert(index, fileCon);
    packetTracker[control_index] = 1;
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
// //                   checkArgs
// //
// //  Validates the arguments from the command line
// // ------------------------------------------------------
void checkArgs(int argc, char *argv[]) {
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

// ------------------------------------------------------
// //                   matchFileHash
// //
// //  Enters the target directory and creates SHA1 hashes 
// // for the files there. Returns whether any of the hashes
// // match the hash coming from the client.
// // ------------------------------------------------------
bool matchFileHash(char *filepath, DIR *TGT, char *incomingMessage) {
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
        
        if (strcmp(incomingMessage, str_obuf.c_str()) == 0) {
            delete t;
            delete buffer;
            matched = true;
            break;
        }
    }
    return matched;
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

// ------------------------------------------------------
// //                   writeFile
// //
// //  Takes the contents from the the file content 
// //  vector and creates a temp file in the target
// //  dircetory with that content
// // ------------------------------------------------------
void writeFile(int nastiness, char *targetDir, string fileName, vector<string> *fileContent) {
    size_t size = fileContent->size();
    string fileCon = "";
    for (size_t i = 0; i < size; i++) {
        fileCon += fileContent->at(i);
    }
    size_t len;
    string errorString;
    char *buffer;
    size_t sourceSize = fileCon.length();
    try {
        buffer = (char *)malloc(sourceSize);
        strncpy(buffer, fileCon.c_str(), sourceSize);
        string targetName = makeFileName(targetDir, fileName + ".TMP");
        NASTYFILE outputFile(nastiness); 
        outputFile.fopen(targetName.c_str(), "wb");  
        len = outputFile.fwrite(buffer, 1, sourceSize);
        if (len != sourceSize) {
            cerr << "Error writing file " << targetName << 
                "  errno=" << strerror(errno) << endl;
            exit(16);
        }
        if (outputFile.fclose() != 0 ) {
            cerr << "Error closing output file " << targetName << 
                " errno=" << strerror(errno) << endl;
            exit(16);
        }
        free(buffer);
    
    } catch (C150Exception e) {
        cerr << "nastyfiletest:copyfile(): Caught C150Exception: " << 
           e.formattedExplanation() << endl;
    }

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

