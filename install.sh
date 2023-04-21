#!/bin/bash

set -e

install -m 0744 ddnspod.py /usr/local/bin/
install -m 0744 ddnspod.conf /etc/
install -m 0744 ddnspod.service /etc/systemd/system/

systemctl enable ddnspod.service
systemctl restart ddnspod.service
