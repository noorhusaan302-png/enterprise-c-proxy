all: proxy

proxy: proxy.c
	gcc proxy.c -o proxy -lpthread

clean:
	rm -f proxy blacklist.txt
