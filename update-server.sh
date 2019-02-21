#!/bin/bash
source ~/.virtualenv/GRR/bin/activate
cd grr
pip install -e grr/proto --progress-bar off
pip install -e api_client/python --progress-bar off
pip install -e grr/core --progress-bar off
pip install -e grr/client --progress-bar off
pip install -e grr/server --progress-bar off
pip install -e grr/server/[mysqldatastore] --progress-bar off
 
