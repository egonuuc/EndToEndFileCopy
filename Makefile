# Makefile for COMP 117 End-to-End assignment
#
#    Copyright 2012 - Noah Mendelsohn
#
#    nastyfiletest - demonstrates the c150nastyfile class that you 
#                    MUST use to read and write your files
#
#    sha1test -   sample code for computing SHA1 hash
#
#    makedatafile -  sometimes when testing file copy programs
#                    it's useful to have files in which it's
#                    relatively easy to spot changes.
#                    This program generates sample data files.

# Do all C++ compies with g++
CPP = g++
CPPFLAGS = -std=c++11 -g -Wall -Werror -I$(C150LIB)

# Where the COMP 150 shared utilities live, including c150ids.a and userports.csv
# Note that environment variable COMP117 must be set for this to work!

C150LIB = $(COMP117)/files/c150Utils/
C150AR = $(C150LIB)c150ids.a

LDFLAGS = 
INCLUDES = $(C150LIB)c150dgmsocket.h $(C150LIB)c150nastydgmsocket.h $(C150LIB)c150network.h $(C150LIB)c150exceptions.h $(C150LIB)c150debug.h $(C150LIB)c150utility.h

all: nastyfiletest makedatafile sha1test fileclient fileserver


#
# Build the nastyfiletest sample
#
nastyfiletest: nastyfiletest.cpp  $(C150AR) $(INCLUDES)
	$(CPP) -o nastyfiletest  $(CPPFLAGS) nastyfiletest.cpp $(C150AR)

#
# Build the sha1test
#
sha1test: sha1test.cpp
	$(CPP) -o sha1test sha1test.cpp -lssl -lcrypto

#
# Build the makedatafile 
#
makedatafile: makedatafile.cpp
	$(CPP) -o makedatafile makedatafile.cpp 

#
# Build file client and file server
#
fileclient: fileclient.o utils.o $(C150AR) $(INCLUDES)
	$(CPP) -o fileclient fileclient.o utils.o $(C150AR) -lssl -lcrypto

fileserver: fileserver.o  utils.o $(C150AR) $(INCLUDES)
	$(CPP) -o fileserver fileserver.o utils.o $(C150AR) -lssl -lcrypto


#
# To get any .o, compile the corresponding .cpp
#
%.o:%.cpp  $(INCLUDES)
	$(CPP) -c  $(CPPFLAGS) $< 


#
# Delete all compiled code in preparation
# for forcing complete rebuild#

clean:
	 rm -f nastyfiletest sha1test makedatafile fileclient fileserver *.o 


