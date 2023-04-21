# DDNSPod

1. curl `ip.sb` to query IPv4 and IPv6 address.
2. curl -X POST `dnspod` api to update domain record.

## Usage

1. update ddnspod.conf as your wish
```conf
# Get your secret id and key from https://console.cloud.tencent.com/cam/capi
SECRET_ID = AKIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
SECRET_KEY = vVxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxd
# your domain
DOMAIN = example.com
# subdomain for this ddns instance
SUB_DOMAIN = ddns
# unnecessary log file
LOG_FILE = /var/log/ddnspod.log
# in seconds
INTERVAL = 300
```

2. install the systemd configurations

```shell
sudo ./install.sh
```

3. directly run `./ddnspod.py` works too, the ddnspod.conf in `$(pwd)` will override the `/etc/` one.

## Remove

```shell
sudo ./uninstall.sh
```