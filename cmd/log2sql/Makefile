

BINARY=log2sql

# These are the values we want to pass for VERSION and BUILD
# git tag 1.0.1
# git commit -am "One more change after the tags"
VERSION=`git describe --tags`
BUILD_DATE=`date +%FT%T%z`
USER=`git config user.email`
BRANCH=`git rev-parse --abbrev-ref HEAD`
REVISION=`git rev-parse --short HEAD`

# Setup the -ldflags option for go build here, interpolate the variable values
MODULE="github.com/rcowham/p4prometheus"
LDFLAGS=-ldflags="-w -s -X ${MODULE}/version.Version=${VERSION} -X ${MODULE}/version.BuildDate=${BUILD_DATE} -X ${MODULE}/version.Branch=${BRANCH} -X ${MODULE}/version.Revision=${REVISION} -X ${MODULE}/version.BuildUser=${USER}"

# Builds the project
build:
	go build ${LDFLAGS}

# Builds distribution
dist:
	~/go/bin/xgo --targets=linux/amd64,windows/amd64,darwin/amd64 ${LDFLAGS} github.com/rcowham/go-libp4dlog/cmd/log2sql 
	# GOOS=linux GOARCH=amd64 go build -o log2sql.linux-amd64 ${LDFLAGS}
	# GOOS=windows GOARCH=amd64 go build -o log2sql.windows-amd64 ${LDFLAGS}
	# go build -o log2sql.darwin-amd64 ${LDFLAGS}
	# -chmod +x log2sql.linux-amd64 p4prometheus.windows-amd64 p4prometheus.darwin-amd64
	# -rm log2sql.linux-amd64.gz p4prometheus.windows-amd64.gz p4prometheus.darwin-amd64.gz
	# gzip log2sql.linux-amd64 p4prometheus.windows-amd64 p4prometheus.darwin-amd64

# Installs our project: copies binaries
install:
	go install ${LDFLAGS_f1}

# Cleans our project: deletes binaries
clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

.PHONY: clean install