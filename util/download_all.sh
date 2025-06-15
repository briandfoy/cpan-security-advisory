#!/bin/sh

mkdir -p downloads
cd downloads
rm -rf *

perl ../util/list_all_releases $1 | while read u; do curl -O $u; done
for f in *.gz; do tar -xzf $f; done
