#!/bin/sh

mkdir -p downloads
cd downloads
rm -rf *

perl -I../util/lib ../util/list_all_releases $1 | while read u; do curl -O $u; done
for f in *.gz; do tar -xzf $f; done
