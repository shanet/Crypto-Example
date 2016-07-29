CC = g++
CFLAGS = -Wall -Wextra -ggdb
LIBS = -lcrypto
SRC = base64.cpp Crypto.cpp

EXAMPLE_TARGET = crypto_example
FILE_EXAMPLE_TARGET = crypto_file_example

all: text file

text:
	$(CC) $(CFLAGS) -o $(EXAMPLE_TARGET) $(SRC) crypto_example.cpp $(LIBS)

file:
	$(CC) $(CFLAGS) -o $(FILE_EXAMPLE_TARGET) $(SRC) crypto_file_example.cpp $(LIBS)

clean:
	rm $(EXAMPLE_TARGET) $(FILE_EXAMPLE_TARGET)

