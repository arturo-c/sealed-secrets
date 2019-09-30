#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

if ! which go > /dev/null; then
   echo "golang needs to be installed"
   exit 1
fi

BIN_DIR="$(pwd)/tmp/_output/bin"
GO_FLAGS = -mod=vendor
mkdir -p ${BIN_DIR}
PROJECT_NAME="sealed-secrets"
BUILD_PATH="./cmd/controller"

if [ $# -gt 0 ] && [ "$1" = "DEBUG" ] ; then
  echo "building "${PROJECT_NAME}" In DEBUG Mode..."
  GOOS=linux go build -gcflags "-N -l" -o ${BIN_DIR}/${PROJECT_NAME}-debug $BUILD_PATH
  cp /usr/local/bin/dlv ${BIN_DIR}
else
  echo "building "${PROJECT_NAME}"..."
  GOOS=linux CGO_ENABLED=0 go build -o ${BIN_DIR}/${PROJECT_NAME} $BUILD_PATH
fi
