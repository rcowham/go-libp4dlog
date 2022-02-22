

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

# Builds distribution - uses xgo and the docker container for cross platform builds
# See: https://github.com/karalabe/xgo
# Note that this will download and build the latest version of package from github - it won't build the local go
# repo. So you need to have published everything (and ensure tags are as desired) before doing this.
dist:
	~/go/bin/xgo --targets=linux/amd64,windows/amd64,darwin/amd64 ${LDFLAGS} github.com/rcowham/go-libp4dlog/cmd/p4dpending
	rm -f p4dpending*amd64*.gz
	-chmod +x p4dpending*amd64*
	gzip p4dpending*amd64*

# Installs our project: copies binaries
install:
	go install ${LDFLAGS_f1}

# Cleans our project: deletes binaries
clean:
	if [ -f ${BINARY} ] ; then rm ${BINARY} ; fi

.PHONY: clean install
