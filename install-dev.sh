#!/bin/sh
sudo apt update -qq
sudo apt install -y locales fakeroot debhelper libffi-dev git attr \
  libssl-dev python-dev python-pip wget openjdk-8-jdk zip devscripts \
  dh-systemd libmysqlclient-dev dh-virtualenv dh-make libc6-i386 lib32z1 asciidoc virtualenv
# Install pip, virtualenv
sudo pip install --upgrade pip wheel setuptools six virtualenv

cd ~ && git clone https://github.com/google/grr.git grr && cd grr
travis/install_protobuf.sh linux
export PROTOC=${HOME}/protobuf/bin/protoc

set -ex
virtualenv --python=/usr/bin/python2.7 ~/.virtualenv/GRR
echo "GRR development virtual environment is at ~/.virtualenv/GRR/"
. ~/.virtualenv/GRR/bin/activate
# Set default value for PROTOC if necessary.
export PROTOC=${HOME}/protobuf/bin/protoc
# Get around a Travis bug: https://github.com/travis-ci/travis-ci/issues/8315#issuecomment-327951718
unset _JAVA_OPTIONS
# This causes 'gulp compile' to fail.
unset JAVA_TOOL_OPTIONS

sudo apt install -y libssl-dev python-dev python-pip wget openjdk-8-jdk zip dh-systemd libmysqlclient-dev mysql-server
pip install --upgrade pip wheel setuptools six nodeenv
# Install the latest version of nodejs. Some packages
# may not be compatible with the version.
nodeenv -p --prebuilt
# Pull in changes to activate made by nodeenv
deactivate
. ~/.virtualenv/GRR/bin/activate
pip install --no-cache-dir -f https://storage.googleapis.com/releases.grr-response.com/index.html grr-response-templates

# Install grr packages as links pointing to code in the checked-out repository.
# Note that because of dependencies, order here is important.
# Proto package.
pip install -e grr/proto --progress-bar off
# Base package, grr-response-core, depends on grr-response-proto.
pip install -e grr/core --progress-bar off
# Depends on grr-response-core
pip install -e api_client/python --progress-bar off
# Depends on grr-response-core
pip install -e grr/client --progress-bar off
# Depends on grr-response-client
pip install -e grr/server/[mysqldatastore] --progress-bar off
# Depends on grr-response-server and grr-api-client
pip install -e grr/test --progress-bar off
# Initialize the development GRR setup
grr_config_updater initialize
