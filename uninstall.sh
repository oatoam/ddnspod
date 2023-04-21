#!/bin/bash

rm -f /usr/local/bin/ddnspod.py
rm -f /etc/ddnspod.conf

systemctl stop ddnspod.service
systemctl disable ddnspod.service
rm -f /etc/systemd/system/ddnspod.service