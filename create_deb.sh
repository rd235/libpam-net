#!/bin/bash
set -x

SOURCE_ROOT=${PWD##*/}
SOURCE_NAME=$(dpkg-parsechangelog --show-field Source)
UPSTREAM_VERSION="$(dpkg-parsechangelog --show-field Version | sed 's/-.*$//')"
( 
cd ..
tar zcvf ${SOURCE_NAME}_${UPSTREAM_VERSION}.orig.tar.gz \
		--transform "s/^${SOURCE_ROOT}/${SOURCE_NAME}-${UPSTREAM_VERSION}/" \
		--exclude "${SOURCE_ROOT}/debian" \
		--exclude "*/.git" \
		--exclude "*/.gitmodules" \
		${SOURCE_ROOT}
)
