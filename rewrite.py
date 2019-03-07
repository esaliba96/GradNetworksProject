#!/usr/bin/env python

import sys
import logging
from datetime import datetime

logging.basicConfig(filename='squid-redirect.log',level=logging.DEBUG)

request  = sys.stdin.readline()
while request:
    [ch_id,url,ipaddr,method,user]=request.split()
    logging.debug(datetime.now().strftime('%Y-%m-%d %H:%M:%S') + ': ' + request +'\n')
    response  = ch_id + ' OK'
    if '.jpg' in url:
        response +=  ' rewrite-url=http://127.0.0.0/image.jpg'
    response += '\n'
    sys.stdout.write(response)
    sys.stdout.flush()
    request = sys.stdin.readline()

