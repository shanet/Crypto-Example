all: text file

text:
	g++ -Wall -Wextra -ggdb -o crypto-example crypto-example.cpp base64.cpp Crypto.cpp -lcrypto

file:
	g++ -Wall -Wextra -ggdb -o crypto-file-example crypto-file-example.cpp base64.cpp Crypto.cpp -lcrypto

clean:
	rm -f crypto-example crypto-file-example

