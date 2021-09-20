lib: loader.c
	gcc -c -Wall -Werror -fpic loader.c
	gcc -shared -o loader.so loader.o

link: loader.so
	export LD_LIBRARY_PATH=/home/leon/graphene/Examples/premain/lib
	gcc -o read read.c -lloader -L/home/leon/graphene/Examples/premain/lib
	
clean:
	rm *.o *.so
