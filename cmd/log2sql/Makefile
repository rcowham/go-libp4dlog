# Makefile for log2sql - cross compiles for Linux/Mac/Windows with Sqlite and CGO

BINARY=log2sql

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
LINUX_LDFLAGS=-ldflags="-extldflags -static -w -s -X ${MODULE}/version.Version=${VERSION} -X ${MODULE}/version.BuildDate=${BUILD_DATE} -X ${MODULE}/version.Branch=${BRANCH} -X ${MODULE}/version.Revision=${REVISION} -X ${MODULE}/version.BuildUser=${USER}"

# Builds the project
build:
	go build ${LOCAL_LDFLAGS}

# Builds distribution - uses xgo and the docker container for cross platform builds with CGO (due to Sqlite bindings)
# See: https://github.com/crazy-max/xgo - (previously was https://github.com/karalabe/xgo)
#    docker pull crazymax/xgo:latest
#    go install github.com/crazy-max/xgo@latest
# Note that this will download and build the latest version of package from github - it won't build the local go
# repo. So you need to have published everything (and ensure tags are as desired) before doing this.
# Temp workaround for problem with xgo docker on M3 not building Linux amd64 - use local version.
# For details see: https://github.com/crazy-max/xgo/issues/124
dist:
	~/go/bin/xgo -docker-image crazymax/xgo:latest -targets=linux/amd64,linux/arm64 -out bin/log2sql ${LINUX_LDFLAGS} github.com/rcowham/go-libp4dlog/cmd/log2sql
	~/go/bin/xgo -docker-image crazymax/xgo:latest -targets=windows/amd64,windows/arm64,darwin/arm64,darwin/amd64 -out bin/log2sql  ${LDFLAGS} github.com/rcowham/go-libp4dlog/cmd/log2sql
	rm -f bin/log2sql*amd64*.gz bin/log2sql*arm64*.gz
	-chmod +x bin/log2sql*amd64* bin/log2sql*arm64* 
	gzip bin/log2sql*amd64* bin/log2sql*arm64*

# Installs our project: copies binaries
install:
	go install ${LDFLAGS_f1}

# Cleans our project: deletes binaries
clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

.PHONY: clean install
