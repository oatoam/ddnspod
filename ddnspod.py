#!/usr/bin/python3
# coding:utf-8

import os
import hashlib
import json
import time
import datetime
import hmac
import logging

LOG_LEVEL = logging.INFO
CONFIG_PATH = "ddnspod.conf"
CONFIG = {
    'SECRET_ID': 'AKIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'SECRET_KEY' : "vVxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxd",
    'DOMAIN' : "example.com",
    'SUB_DOMAIN' : "ddns",
    'INTERVAL' : 300,
}

def parse_config(path=CONFIG_PATH):
    with open(path, 'r') as config:
        while True:
            line = config.readline()
            if len(line) == 0:
                break
            if line[0] == '#':
                continue
            ele = line.split('=')
            if len(ele) == 2:
                CONFIG[ele[0].strip()] = ele[1].strip()


parse_config()

IP_SERVER = "ip.sb"
VERSION = '2021-03-23'
REGION = None
ALGORITHM = 'TC3-HMAC-SHA256'
SERVICE = 'dnspod'
HOST = SERVICE + '.tencentcloudapi.com'
ENDPOINT = 'https://' + HOST

logging.basicConfig(level=LOG_LEVEL, filename=CONFIG['LOG_FILE'],
                    format='%(asctime)s %(levelname)s [%(filename)s:%(lineno)d] %(message)s',
                    datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__file__.split('/')[-1])


def gen_authorization(type: str, uri: str, query: str, headers: str, headerkeys: str, payload: str, date: str, timestamp: int):
    """
    ref: https://github.com/TencentCloud/signature-process-demo/blob/main/cvm/signature-v3/python/demo.py
    """
    logger.debug('payload: [%s]' % payload)
    canonical_request = (type + "\n" + uri + "\n" +
                         query + "\n" + headers + "\n" + headerkeys + "\n" +
                         hashlib.sha256(payload).hexdigest())
    logger.debug('canonical_request: [%s]' % canonical_request)
    scope = "%s/%s/tc3_request" % (date, SERVICE)
    string_to_sign = (ALGORITHM + "\n" + str(timestamp) + "\n" +
                      scope + "\n" +
                      hashlib.sha256(canonical_request.encode('utf-8')).hexdigest())
    logger.debug('string_to_sign: [%s]' % string_to_sign)

    def calc(key, msg):
        return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    secret_date = calc(("TC3" + CONFIG['SECRET_KEY']).encode('utf-8'), date)
    secret_service = calc(secret_date, SERVICE)
    secret_signing = calc(secret_service, "tc3_request")
    signature = hmac.new(secret_signing, string_to_sign.encode(
        "utf-8"), hashlib.sha256).hexdigest()
    logger.debug('signature: [%s]' % signature)
    authorization = (ALGORITHM + " " +
                     "Credential=" + CONFIG['SECRET_ID'] + "/" + scope + ", " +
                     "SignedHeaders=" + headerkeys + ", " +
                     "Signature=" + signature)
    return authorization


def test_gen_authorization():
    """
    验证生成结果的正确性
    https://console.cloud.tencent.com/api/explorer?Product=dnspod&Version=2021-03-23&Action=DescribeRecord
    """
    timestamp = int(time.time())
    date = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
    method = 'POST'
    uri = '/'
    query = ''
    action = 'describerecord'
    headers = "content-type:application/json\nhost:%s\nx-tc-action:%s\n" % (
        HOST, action)
    headerkeys = "content-type;host;x-tc-action"
    # {"Limit": 1, "Filters": [{"Values": ["\u672a\u547d\u540d"], "Name": "instance-name"}]}
    payload = {"Domain": "ddns"}
    logger.debug(gen_authorization(method, uri, query, headers,
                 headerkeys, payload, date, timestamp))


def check_error(resp):
    resp = json.loads(resp)
    if 'Response' in resp and 'Error' in resp['Response']:
        logger.error('error response from server')
        raise Exception(resp)


def post(action: str, payload: object):
    """ 发送请求 """
    logger.debug(f'post(action={action}, payload={payload})')
    timestamp = int(time.time())
    date = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d')
    method = 'POST'
    uri = '/'
    query = ''
    headers = "content-type:application/json\nhost:%s\nx-tc-action:%s\n" % (
        HOST, action.lower())
    headerkeys = "content-type;host;x-tc-action"
    if not isinstance(payload, str):
        payload = json.dumps(payload)
    # payload = '{"Domain":"ddns"}'
    authorization = gen_authorization(
        method, uri, query, headers, headerkeys, payload.encode('utf-8'), date, timestamp)
    logger.debug(authorization)
    cmd = ('curl ' +
           ' -H "Authorization: ' + authorization + '"' +
           ' -H "Content-Type: application/json"' +
           ' -H "Host: ' + HOST + '"' +
           ' -H "X-TC-Language: zh-CN"' +
           ' -H "X-TC-Action: ' + action + '"' +
           ' -H "X-TC-Timestamp: ' + str(timestamp) + '"' +
           ' -H "X-TC-Version: ' + VERSION + '"' +
           # ' -H "X-TC-Region: ' + REGION + '"' +
           " -d '" + payload + "' -s " + ENDPOINT)
    logger.debug(cmd)
    resp = os.popen(cmd).read()
    check_error(resp)
    return resp


def describe_record_list(domain: str, subdomain: str = None, recordtype: str = None):
    payload = {"Domain": domain}
    if subdomain is not None:
        payload['Subdomain'] = subdomain
    if recordtype is not None:
        payload['RecordType'] = recordtype
    resp = post('DescribeRecordList', payload)
    return resp


def describe(domain: str, recordid: int, domainid: int = None):
    payload = {"Domain": domain, "RecordId": recordid}
    if domainid is not None:
        payload["DomainId"] = domainid
    resp = post('DescribeRecord', payload)
    return resp


def create_record(domain: str, recordtype: str, recordline: str, value: str, subdomain: str = None, ttl: int = None):
    payload = {
        "Domain": domain,
        "RecordType": recordtype,
        "RecordLine": recordline,
        "Value": value,
    }
    if subdomain is not None:
        payload['SubDomain'] = subdomain
    if ttl is not None:
        payload['TTL'] = ttl
    resp = post('CreateRecord', payload)
    resp = json.loads(resp)

    if 'Error' in resp['Response']:
        logger.error("failed")
        return -1
    return resp['Response']['RecordId']


def delete_record(domain: str, recordid: int, domainid: int = None):
    payload = {"Domain": domain, "RecordId": recordid}
    if domainid is not None:
        payload["DomainId"] = domainid
    resp = post('DeleteRecord', payload)
    return resp


def modify_record(domain: str, recordid: int, recordtype: str, recordline: str, value: str, subdomain: str = None, domainid: int = None, ttl: int = None):
    payload = {"Domain": domain, "RecordId": recordid,
               "RecordType": recordtype, "RecordLine": recordline,
               "Value": value}
    if domainid is not None:
        payload["DomainId"] = domainid
    if subdomain is not None:
        payload["SubDomain"] = subdomain
    if ttl is not None:
        payload["TTL"] = ttl
    resp = post("ModifyRecord", payload)
    return resp


def update_record(domain: str, subdomain: str, recordtype: str, value: str):
    logger.info(f'update_record {domain} {subdomain} {recordtype} {value}')
    # get current record
    resp = describe_record_list(domain, subdomain, recordtype)
    logger.debug(resp)
    resp = json.loads(resp)
    if resp['Response'] and 'RecordList' in resp['Response']:
        recordid = resp['Response']['RecordList'][0]['RecordId']
        remote_value = resp['Response']['RecordList'][0]['Value']
        if value == remote_value:
            logger.info("record was not changed")
            return
        logger.debug(
            f"{domain} {subdomain} {recordtype} from {remote_value} to {value}")
        resp = modify_record(domain, recordid, recordtype,
                             '默认', value, subdomain=subdomain)
        logger.debug(resp)
    else:
        logger.debug("create record %s(%s) = %s" %
                     (subdomain, recordtype, value))
        resp = create_record(domain, recordtype, '默认',
                             value, subdomain=subdomain)
        logger.debug(resp)


def is_ipv4(address):
    #TODO
    return True


def is_ipv6(address):
    #TODO
    return True


def ddns():
    ipv4 = os.popen(f'curl -s -4 {IP_SERVER}').read()
    if len(ipv4) and ipv4[-1] == '\n':
        ipv4 = ipv4[:-1]
    logger.debug(f"new ipv4 address is {ipv4}")
    ipv6 = os.popen(f'curl -s -6 {IP_SERVER}').read()
    if len(ipv6) and ipv6[-1] == '\n':
        ipv6 = ipv6[:-1]
    logger.debug(f"new ipv6 address is {ipv6}")
    if len(ipv4) and is_ipv4(ipv4):
        update_record(CONFIG['DOMAIN'], CONFIG['SUB_DOMAIN'], 'A', ipv4)
    if len(ipv6) and is_ipv6(ipv6):
        update_record(CONFIG['DOMAIN'], CONFIG['SUB_DOMAIN'], 'AAAA', ipv6)


def main():
    while True:
        ddns()
        time.sleep(int(CONFIG['INTERVAL']))


if __name__ == '__main__':
    main()
