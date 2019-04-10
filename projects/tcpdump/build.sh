#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

cd $SRC/libpcap
mkdir build
cd build
cmake ..
make
make install

cd $SRC/tcpdump
mkdir build
cd build
cmake ..
make

# Not needed for fuzzing but useful as a product for replication with ASAN
cp tcpdump $OUT/

# Now hand it over to the script in the tcpdump repo
exec $SRC/tcpdump/fuzz/build.sh
