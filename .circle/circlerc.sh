#!/bin/bash

if [ -z "$extCIRCLE_DIR" ]; then
  path=$(readlink -f $0)
  dir=$(dirname $path)
  echo "export extCIRCLE_DIR=${dir}" >> ~/.circlerc
  echo ". ${dir}/circlerc.sh" >> ~/.circlerc
  exit 0
fi

pushd $extCIRCLE_DIR >/dev/null

# Source our extensions during a command invocation
  . ./env
  . ./helpers.sh

popd >/dev/null