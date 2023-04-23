#!/bin/bash

systemctl stop ddnspod.service
systemctl disable ddnspod.service

rm -f /usr/local/bin/ddnspod.py
rm -f /etc/ddnspod.conf
rm -f /etc/systemd/system/ddnspod.service