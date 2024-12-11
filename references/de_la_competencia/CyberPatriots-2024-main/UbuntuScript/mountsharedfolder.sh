#!/bin/bash

mkdir /mnt/hgfs
vmhgfs-fuse .host:/ /mnt/hgfs/ -o allow_other -o uid=1000
