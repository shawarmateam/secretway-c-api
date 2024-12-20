# vars
BUILD_D = bin
CODE_D = src
FILES = ${CODE_D}/main.cpp ${CODE_D}/secretway-api.cpp
ARGS = -lssl -lcrypto -lmongocxx -lbsoncxx -I/usr/include/mongocxx/v_noabi -I/usr/include/bsoncxx/v_noabi -Wdeprecated-declarations

# cmds
all: build

build: ./${CODE_D}/main.cpp
	mkdir -p bin/
	g++ -o ${BUILD_D}/main ${FILES} ${ARGS}

lib: ./${CODE_D}/secretway-api.cpp
	mkdir -p bin/
	g++ -shared -o bin/secretway.so -fPIC src/secretway-api.cpp

run: build
	./${BUILD_D}/main

clean:
	rm -rf ./${BUILD_D}/*


# aliases
clr: clean
