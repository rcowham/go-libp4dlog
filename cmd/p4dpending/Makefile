# Build file for p4dpending - useful debugging tool for the library

BINARY=p4dpending

# These are the values we want to pass for VERSION and BUILD
VERSION=`git describe --tags`
BUILD_DATE=`date +%FT%T%z`
USER=`git config user.email`
BRANCH=`git rev-parse --abbrev-ref HEAD`
REVISION=`git rev-parse --short HEAD`

# Setup the -ldflags option for go build here, interpolate the variable values.
# Note the Version module is in a different git repo.
MODULE="github.com/perforce/p4prometheus"
LOCAL_LDFLAGS=-ldflags="-X ${MODULE}/version.Version=${VERSION} -X ${MODULE}/version.BuildDate=${BUILD_DATE} -X ${MODULE}/version.Branch=${BRANCH} -X ${MODULE}/version.Revision=${REVISION} -X ${MODULE}/version.BuildUser=${USER}"
LDFLAGS=-ldflags="-w -s -X ${MODULE}/version.Version=${VERSION} -X ${MODULE}/version.BuildDate=${BUILD_DATE} -X ${MODULE}/version.Branch=${BRANCH} -X ${MODULE}/version.Revision=${REVISION} -X ${MODULE}/version.BuildUser=${USER}"

# Builds the project
build:
	go build ${LOCAL_LDFLAGS}

test:
	go test

# Builds distribution - for all supported platforms
dist:
	GOOS=darwin GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY}-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY}-darwin-arm64 main.go
	GOOS=linux GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY}-linux-amd64 main.go
	GOOS=linux GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY}-linux-arm64 main.go
	GOOS=windows GOARCH=amd64 go build ${LDFLAGS} -o bin/${BINARY}-windows-amd64.exe main.go
	GOOS=windows GOARCH=arm64 go build ${LDFLAGS} -o bin/${BINARY}-windows-arm64.exe main.go
	rm -f bin/${BINARY}*-a*64*.gz
	-chmod +x bin/${BINARY}*-a*64*
	gzip bin/${BINARY}*a*64*

# Installs our project: copies binaries
install:
	go install ${LDFLAGS_f1}

# Cleans our project: deletes binaries
clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

.PHONY: clean install test
