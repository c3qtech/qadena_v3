#!/bin/zsh

echo "Removing hidapi and libusb from vendor directory"
chmod -R u+w vendor/github.com/zondax/hid/hidapi
chmod -R u+w vendor/github.com/zondax/hid/libusb
rm -rf vendor/github.com/zondax/hid/hidapi
rm -rf vendor/github.com/zondax/hid/libusb

echo "Updating vendor directory"
go mod tidy
go mod vendor

echo "Adding hidapi and libusb to vendor directory"
go get github.com/zondax/hid@v0.9.2
cp -r ~/go/pkg/mod/github.com/zondax/hid@v0.9.2/hidapi vendor/github.com/zondax/hid
cp -r ~/go/pkg/mod/github.com/zondax/hid@v0.9.2/libusb vendor/github.com/zondax/hid
