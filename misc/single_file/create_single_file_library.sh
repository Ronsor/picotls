#!/bin/sh

# Where to find the sources
PTLS_SRC_ROOT="../../"

if test "$1" = "--minilibc" || test "$2" = "--minilibc"; then
  COMBINE_EXTRA_ARGS="-D PICOTLS_MINILIBC -f stdint.h -f stddef.h -f stdarg.h -s"
else
  COMBINE_EXTRA_ARGS=""
fi

if test "$1" != "--openssl" && test "$2" != "--openssl"; then
  COMBINE_EXTRA_ARGS="$COMBINE_EXTRA_ARGS -D PICOTLS_NO_OPENSSL"
fi

# Amalgamate the sources
echo "Amalgamating files..."
# Using the faster Python script if we have 3.8 or higher
if python3 -c 'import sys; assert sys.version_info >= (3,8)' 2>/dev/null; then
  ./combine.py -D PICOTLS_SINGLE_FILE \
               -r "$PWD" -r "$PWD/stubs" -r "$PTLS_SRC_ROOT" \
               -r "$PTLS_SRC_ROOT/include" -r "$PTLS_SRC_ROOT/lib/cifra" \
               -r "$PTLS_SRC_ROOT/deps/cifra/src" -r "$PTLS_SRC_ROOT/deps/micro-ecc" \
               $COMBINE_EXTRA_ARGS -o picotls-full.c picotls-in.c
  ./combine.py -D PICOTLS_SINGLE_FILE \
               -r "$PWD" -r "$PWD/stubs" -r "$PTLS_SRC_ROOT/include" \
               $COMBINE_EXTRA_ARGS -o picotls-full.h picotls-in.h
else
  echo "Python 3.8 or newer is required"
  false
fi
# Did combining work?
if [ $? -ne 0 ]; then
  echo "Combine script: FAILED"
  exit 1
fi
echo "Combine script: PASSED"
