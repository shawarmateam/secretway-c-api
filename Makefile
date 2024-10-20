# vars
BUILD_D = bin
CODE_D = src
CODE_GO_D = src-golang
FILES = ${CODE_D}/main.c ${CODE_D}/secretway-api.c

# cmds
all: build

build: ./${CODE_D}/main.c
	gcc -o ${BUILD_D}/main.o ${FILES}

run: build
	./${BUILD_D}/main.o

clean:
	rm -rf ./${BUILD_D}/*


# aliases
clr: clean
