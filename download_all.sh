#!/bin/sh

mkdir -p downloads
cd downloads
rm -rf *

perl ../util/list_all_releases $1 | while read u; do curl -O $u; done
for f in *.gz; do tar -xzf $f; done

find . -name *jquery* | while read f; do grep 'jQuery Library' $f; done | sort
