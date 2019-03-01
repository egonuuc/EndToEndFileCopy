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
#include <math.h>

using namespace std;          // for C++ std library
using namespace C150NETWORK;  // for all the comp150 utilities 

// forward declarations
void checkAndPrintMessage(ssize_t readlen, char *buf, ssize_t bufferlen);
void setUpDebugLogging(const char *logname, int argc, char *argv[]);
string makeFileName(string dir, string name);
void checkDirectory(char *dirname);
void shaEncrypt(unsigned char *hash, const unsigned char *message);
void preprocessFiles(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *fileNames, queue<string> *fileContent, int network_nastiness);
void printFileHash(unsigned char *hash, char *file_name);
void checkArgs(int argc, char *argv[]);
void checkMsg(char (&incomingMessage)[512], ssize_t readlen);
int createPackets(string fileCon, vector<string> *packets);
bool isFile(string fname);
void readFile(int nastiness, string filePath, queue<string> *fileContent);

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
    queue<string> fileNames;
    queue<string> fileContent;
    vector<string> packets; 
    int file_num = 0;
    int transmission_attempt = 0, end_to_end_attempt = 0, confirmation_attempt = 0;
    string pktList[] = {"MISSING", "SEND_MORE", "RECEIVED_ALL"};
    string msgList[] = {"BEGIN_TRANSMIT", "COMPLETED_TRANSMIT", "MATCHED_CHECKSUM", "WRONG_CHECKSUM", "ACKNOWLEDGEMENT"};
    int totalPacketNum = 0;
    int oneTime = 0, oneTime2 = 0;

    // DO THIS FIRST OR YOUR ASSIGNMENT WON'T BE GRADED!
    GRADEME(argc, argv);

    // Check command line arguments
    checkArgs(argc, argv);
    network_nastiness = atoi(argv[2]); // convert command line string to int
    file_nastiness = atoi(argv[3]); // convert command line string to int
    checkDirectory(argv[4]); // make sure source dir exists

    (void) network_nastiness; // TODO: to delete

    // Set up debug message logging
    setUpDebugLogging("fileclientdebug.txt",argc, argv);

    // open source dir
    SRC = opendir(argv[4]);
    if (SRC == NULL) {
        fprintf(stderr,"Error opening source directory %s\n", argv[4]);
        exit(8);
    }
    preprocessFiles(argv[4], SRC, &shaCodes, &fileNames, &fileContent, file_nastiness);
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

        while(!fileNames.empty()) {

            // WRITE BEGIN_TRANSMIT:<fileName>:<totalPacketNum>
            string fileName = fileNames.front();
            string fileCon = fileContent.front();
            totalPacketNum = createPackets(fileCon, &packets);
            //printf("0 File to transmit is %s\n", file.c_str());
            string initMsg = (msgList[0] + ":" + fileName + ":" + to_string(totalPacketNum)).c_str();
            sock -> write(initMsg.c_str(), strlen(initMsg.c_str())+1);
            *GRADING << "File: " << fileName << ", beginning transmission, attempt "
                << transmission_attempt << endl;
            cout << "**************** BEGIN TRANSMIT ************** " << endl;
            // TRANSMIT FILES
            // _ _ _ _ 4 chars for control info; 508 chars for file content

            int count = 1;
            int batchSize = 10;
            while(1) {
                if (totalPacketNum <= batchSize) {
                    while (count <= totalPacketNum) {
                        cout << packets[count-1] << endl;
                        sock -> write(packets[count-1].c_str(), strlen(packets[count-1].c_str())+1);
                        count++;
                    }
                    // wait & read to see if packets missing or not
                    readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
                    checkMsg(incomingMessage, readlen);
                    // read MISSING
                    if (strcmp(incomingMessage, pktList[0].c_str()) == 0) {
                        cout << " ************ read MISSING **********" << endl;
                        // decrement count once only
                        if (oneTime++ == 0) {
                            count = 1;
                        }
                        // resend
                        continue;
                    // read RECEIVED_ALL
                    } else if (strcmp(incomingMessage, pktList[2].c_str()) == 0) {
                        cout << " ************ read RECEIVED ALL **********" << endl;
                        oneTime = 0;
                        oneTime2 = 0;
                        count = 1;
                        break;
                    } else {
                        throw C150NetworkException("Something has gone wrong");	
                    }
                } else {
                    while (count < totalPacketNum) {
                        int goUpTo = count + batchSize; 
                        while (count < goUpTo) {
                            cout << packets[count-1] << endl;
                            sock -> write(packets[count-1].c_str(), strlen(packets[count-1].c_str())+1);
                            count++;
                        }
                        // wait & read to see if packets missing or not
                        readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
                        checkMsg(incomingMessage, readlen);
                        
                        // read MISSING
                        if (strcmp(incomingMessage, pktList[0].c_str()) == 0) {
                            cout << " ************ read MISSING **********" << endl;
                            if (oneTime2++ == 0) {
                                count -= batchSize+1;
                            }
                            continue;
                        // read SEND_MORE
                        } else if (strcmp(incomingMessage, pktList[1].c_str()) == 0) {
                            cout << " ************ read SEND MORE **********" << endl;
                            cout << " count : " << count << endl;
                            cout << " packets left to send : " << totalPacketNum - count << endl;
                            cout << " batch size : " << batchSize << endl;
                            if (totalPacketNum - count <= batchSize) {
                                // same as base case
                                while (count <= totalPacketNum) {
                                    cout << packets[count-1] << endl;
                                    sock -> write(packets[count-1].c_str(), strlen(packets[count-1].c_str())+1);
                                    count++;
                                }
                                // wait & read to see if packets missing or not
                                readlen = sock -> read(incomingMessage, sizeof(incomingMessage)-1);
                                checkMsg(incomingMessage, readlen);
                                // read MISSING
                                if (strcmp(incomingMessage, pktList[0].c_str()) == 0) {
                                    cout << " ************ read MISSING **********" << endl;
                                    // decrement count once only
                                    if (oneTime++ == 0) {
                                        count -= batchSize+1;
                                    }
                                    // resend
                                    continue;
                                // read RECEIVED_ALL
                                } else if (strcmp(incomingMessage, pktList[2].c_str()) == 0) {
                                    cout << " ************ read RECEIVED ALL **********" << endl;
                                    oneTime = 0;
                                    oneTime2 = 0;
                                    count = 1;
                                    break;
                                } else {
                                    throw C150NetworkException("S2omething has gone wrong");	
                                }
                            } else {
                                continue; // problem
                            }
                        }
                    }
                }
                break;
            }

            // WRITE COMPLETED_TRANSMIT
            sock -> write(msgList[1].c_str(), strlen(msgList[1].c_str())+1); 
            *GRADING << "File: " << fileName << " transmission complete, waiting "
                << "for end-to-end check, attempt " << end_to_end_attempt 
                << endl;

            // WRITE FILE HASH
            sock -> write(shaCodes[file_num].c_str(), strlen(shaCodes[file_num].c_str())+1); 
            //printFileHash((unsigned char *)shaCodes[file_num].c_str(), (char *)fileName.c_str());

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
                cout << "File: " << fileName << " end-to-end check SUCCEEDED -- "
                    << "informing server" << endl;
                sock -> write(msgList[2].c_str(), strlen(msgList[2].c_str())+1);
                end_to_end_attempt = 0;
                transmission_attempt = 0;
            } 
            // If received WRONG_CHECKSUM, retry file transmission
            else if (strcmp(incomingMessage, msgList[3].c_str()) == 0) {
                *GRADING << "File: " << fileName << " end-to-end check failed, "
                    << "attempt " << ++end_to_end_attempt << endl;
                if (end_to_end_attempt < 5) {
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
                *GRADING << "File: " << fileName << " end-to-end check succeeded, "
                    << "attempt " << confirmation_attempt << endl;
                ++file_num;
                oneTime = 0;
                oneTime2 = 0;
                count = 1;
                fileContent.pop();
                fileNames.pop();
                packets.clear();
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

int createPackets(string fileCon, vector<string> *packets) {
    int packetno = 0;
    int offset = 0;
    size_t i;
    size_t fileSize = fileCon.length();
    size_t controlSize = 4;
    size_t count = 0;

    // cout << "String size " << fileSize << endl;
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
                cout << " ***** i " << i << endl;
                cout << " ***** offset " << offset << endl;
                cout << " ***** filesize " << fileSize << endl;
                int ind = i + controlSize;
                cout << " ADDING AT " << ind << endl;
                packet[ind] = '\0';
                break;
            }
            packet[i + controlSize] = fileCon[i + offset];  
        }
        string p(packet);
        packets->push_back(p);
        packetno++;
        offset += 507;
        count++;
    }
    return packetno;
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

        cout << " ******** SOURCE SIZE " << sourceSize << endl;
        cout << " ******** STRING CONTENT SIZE " << content.length() << endl;
    
    }   catch (C150Exception e) {
        cerr << "nastyfiletest:copyfile(): Caught C150Exception: " << 
            e.formattedExplanation() << endl;
    }
}
void preprocessFiles(char *filepath, DIR *SRC, vector<string> *shaCodes, queue<string> *fileNames, queue<string> *fileContent, int nastiness) {
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

// ------------------------------------------------------
//
//                   isFile
//
//  Make sure the supplied file is not a directory or
//  other non-regular file.
//     
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
