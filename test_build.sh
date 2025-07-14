#!/bin/bash
# Script to test PlatformIO build for ESP32 example
set -e
cd "$(dirname "$0")/examples"
echo "Building ESP32 example with PlatformIO..."
pio run
RESULT=$?
if [ $RESULT -eq 0 ]; then
  echo "Build succeeded!"
else
  echo "Build failed!"
fi
exit $RESULT
