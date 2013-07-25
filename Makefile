all:
	g++ -o crypto-example crypto-example.cpp Crypto.cpp -lcrypto

clean:
	rm -f crypto-example

