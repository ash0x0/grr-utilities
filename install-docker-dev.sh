#!/bin/sh
export DEBIAN_FRONTEND="noninteractive"
apt update -qq
apt install -y git wget locales fakeroot debhelper libffi-dev git attr \
  libssl-dev python-dev python-pip wget openjdk-8-jdk zip devscripts \
  dh-systemd libmysqlclient-dev dh-virtualenv dh-make libc6-i386 lib32z1 asciidoc virtualenv

# Install pip, virtualenv
pip install --upgrade pip wheel setuptools six virtualenv

wget --quiet https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb && \
apt install -y ./google-chrome-stable_current_amd64.deb && \
sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
locale-gen && \
update-locale LANG="en_US.UTF-8" LANGUAGE="en_US:en" LC_ALL="en_US.UTF-8"
# Add chrome to PATH and set locale-related environment variables.
PATH="${PATH}:/opt/google/chrome" LANG="en_US.UTF-8" LANGUAGE="en_US:en" LC_ALL="en_US.UTF-8"

cd ~ && git clone https://github.com/google/grr.git grr && cd grr
travis/install_protobuf.sh linux
export PROTOC=${HOME}/protobuf/bin/protoc
set -ex

virtualenv --python=/usr/bin/python2.7 ~/.virtualenv/GRR
. ~/.virtualenv/GRR/bin/activate
# Set default value for PROTOC if necessary.
export PROTOC=${HOME}/protobuf/bin/protoc
export DEBIAN_FRONTEND="noninteractive"
# Get around a Travis bug: https://github.com/travis-ci/travis-ci/issues/8315#issuecomment-327951718
unset _JAVA_OPTIONS
# This causes 'gulp compile' to fail.
unset JAVA_TOOL_OPTIONS

apt install -y libssl-dev python-dev python-pip wget openjdk-8-jdk zip dh-systemd libmysqlclient-dev mysql-server
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

deactivate
