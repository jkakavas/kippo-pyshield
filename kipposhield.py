#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) Ioannis Kakavas
#
#
# kipposhield.py is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# kipposhield.py is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with kipposhield.py.  If not, see <http://www.gnu.org/licenses/>.
#
#
# Adapted from https://isc.sans.edu/clients/kippo/kippodshield.pl

__author__ = "Yiannis Kakavas"
__license__ = "GPL"
__version__ = "0.1"
__email__ = "jkakavas@gmail.com"

import re
import requests
import base64
import sys
import hmac
import hashlib



def send_log(attempts):
    auth_key = ''
    dshield_userid = ''
    log_output = ''
    # Format login attempts as tab seperated log entries
    for logline in attempts:
        log_output += '{0}\t{1}\t{2}\t{3}\t{4}\t{5}\n'.format(logline['date'],logline['time'],logline['timezone'],logline['source_ip'],logline['user'],logline['pwd'])
    # The nonce is predefined as explained in the original script :
    # trying to avoid sending the authentication key in the "clear" but not wanting to
    # deal with a full digest like exchange. Using a fixed nonce to mix up the limited
    # userid. 
    nonce = base64.b64decode('ElWO1arph+Jifqme6eXD8Uj+QTAmijAWxX1msbJzXDM=')
    digest = base64.b64encode(hmac.new('{0}{1}'.format(nonce,dshield_userid),base64.b64decode(auth_key),  hashlib.sha256).digest())
    auth_header = 'credentials={0} nonce=ElWO1arph+Jifqme6eXD8Uj+QTAmijAWxX1msbJzXDM= userid={1}'.format(digest, dshield_userid)
    headers = {'X-ISC-Authorization': auth_header,
              'Content-Type':'text/plain',
              'Content-Length':len(log_output)}
    req = requests.request(method ='PUT',
                           url = 'https://secure.dshield.org/api/file/sshlog',
                           headers = headers,
                           timeout = 10,
                           verify = True,
                           data = log_output)
    if req.status_code == requests.codes.ok:
        print 'response is ok'
        response = req.text
        sha1_regex = re.compile(ur'<sha1checksum>([^<]+)<\/sha1checksum>')
        sha1_match = sha1_regex.search(response)
        if sha1_match is None:
            print 'Could not find sha1checksum in response'
            print 'Response was {0}'.format(response)
            return (1, 'Could not find sha1checksum in response')
        sha1_local = hashlib.sha1()
        sha1_local.update(log_output)
        if sha1_match.group(1) != sha1_local.hexdigest():
            print '\nERROR: SHA1 Mismatch {0} {1} .\n'.format(sha1_match.group(1), sha1_local.hexdigest())
            return(1,'\nERROR: SHA1 Mismatch {0} {1} .\n'.format(sha1_match.group(1), sha1_local.hexdigest()))
        md5_regex = re.compile(ur'<md5checksum>([^<]+)<\/md5checksum>')
        md5_match = md5_regex.search(response)
        if md5_match is None:
            print 'Could not find md5checksum in response'
            print 'Response was {0}'.format(response)
            return (1, 'Could not find md5checksum in response')
        md5_local = hashlib.md5()
        md5_local.update(log_output)
        if md5_match.group(1) != md5_local.hexdigest():
            print '\nERROR: MD5 Mismatch {0} {1} .\n'.format(md5_match.group(1), md5_local.hexdigest())
            return(1,'\nERROR: MD5 Mismatch {0} {1} .\n'.format(md5_match.group(1), md5_local.hexdigest()))
        print '\nSUCCESS: Sent {0} bytes worth of data to secure.dshield.org\n'.format(len(log_output))
        return(0,'\nSUCCESS: Sent {0} bytes worth of data to secure.dshield.org\n'.format(len(log_output)))
    else:
        print '\nERROR: error {0} .\n'.format(req.status_code)
        print 'Response was {0}'.format(response)
        return(1,'\nERROR: error {0} .\n'.format(req.status_code))

def analyze_log(logfile_path):
    # We attempt to match log lines like the one below:
    # 2015-09-09 11:28:09+0300 [SSHService ssh-userauth on HoneyPotTransport,1579,24.39.252.180] login attempt [root/alpine] succeeded
    regex = re.compile(ur"(2\d\d\d-\d\d-\d\d) (\d\d:\d\d:\d\d)([+-]\d{4}) [^,]+,\d+,([\d.]+)\] login attempt \[([^\/]+)\/([^\]]+)\]")
    attempts = []

    with open(logfile_path, 'r') as logfile:
        for line in logfile.readlines():
            match = regex.search(line.rstrip())
            if match is not None:
                attempts.append({'date':match.group(0),
                                 'time':match.group(1),
                                 'timezone':match.group(2),
                                 'source_ip':match.group(3),
                                 'user':match.group(4),
                                 'pwd':match.group(5)
                                })
    return attempts


def main():
    attempts = analyze_log(sys.argv[1])
    if len(attempts) == 0:
        print 'INFO: No login attempts found in the specified log file ({0})'.format(sys.argv[1])
        sys.exit(0)
    # Split log entries in chunks of 1000
    print 'INFO: Found {0} login attempts in the specified log file ({1})'.format(len(attempts),sys.argv[1])
    if len(attempts) > 1000:
        print 'INFO: Splitting log entries in chunks of 1000 entries'
        attempts_chunks = [attempts[x:x+1000] for x in xrange(0, len(attempts), 1000)]
        for chunk in attempts_chunks:
            print 'INFO: Sending chunk to the server'
            result_code,result = send_log(chunk)
    else:
        print 'INFO: Sending all entries to the server'
        result_code,result = send_log(attempts)
    sys.exit(result_code)


if __name__ == "__main__":
    main()
