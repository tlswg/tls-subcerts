#! /bin/sh
if [ ! -d /mount/keys ]; then
  mkdir /mount/keys
fi
cp *.pem /mount/keys/
cp dc.cred /mount/keys/
