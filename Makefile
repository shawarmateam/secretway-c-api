# vars
BUILD_D = bin
CODE_D = src
FILES = ${CODE_D}/main.cpp ${CODE_D}/secretway-api.cpp
#${CODE_D}/env_parser.cpp

# cmds
all: build

build: ./${CODE_D}/main.cpp
	mkdir -p bin/
	g++ -o ${BUILD_D}/main.o ${FILES}

run: build
	./${BUILD_D}/main.o

clean:
	rm -rf ./${BUILD_D}/*


# aliases
clr: clean
