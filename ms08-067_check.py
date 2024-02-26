#!/usr/bin/env python

'''
Name: Microsoft Server Service Remote Path Canonicalization Stack Overflow Vulnerability

Description:
Anonymously check if a target machine is affected by MS08-067 (Vulnerability in Server Service Could Allow Remote Code Execution)

Author: Bernardo Damele A. G. <bernardo.damele@gmail.com>

License: Modified Apache 1.1

Version: 0.6

References:
* BID: 31874
* CVE: 2008-4250
* MSB: MS08-067
* VENDOR: http://blogs.technet.com/swi/archive/2008/10/25/most-common-questions-that-we-ve-been-asked-regarding-ms08-067.aspx
* VENDOR: http://www.microsoft.com/technet/security/advisory/958963.mspx
* MISC: http://www.phreedom.org/blog/2008/decompiling-ms08-067/
* MISC: http://metasploit.com/dev/trac/browser/framework3/trunk/modules/exploits/windows/smb/ms08_067_netapi.rb
* MISC: http://blog.threatexpert.com/2008/10/gimmiva-exploits-zero-day-vulnerability.html
* MISC: http://blogs.securiteam.com/index.php/archives/1150

Tested:
* Windows 2000 Server Service Pack 0
* Windows 2000 Server Service Pack 4 with Update Rollup 1
* Microsoft 2003 Standard Service Pack 1
* Microsoft 2003 Standard Service Pack 2 Full Patched at 22nd of October 2008, before MS08-067 patch was released

Notes:
* On Windows XP SP2 and SP3 this check might lead to a race condition and
  heap corruption in the svchost.exe process, but it may not crash the
  service immediately: it can trigger later on inside any of the shared
  services in the process.
'''

import sys
import struct

from optparse import OptionError
from optparse import OptionParser

try:
    from impacket.dcerpc.v5 import transport, srvs
    from impacket.uuid import uuidtup_to_bin
except ImportError as _:
    print('ERROR: this tool requires python-impacket library to be installed, get it ')
    print('from http://oss.coresecurity.com/projects/impacket.html or apt-get install python-impacket')
    sys.exit(1)

# CONSTANTS
CMDLINE = False
SILENT = False

# CLASS


class MS08_067:
    def __init__(self, target, port=445):
        # super(MS08_067, self).__init__()

        self.__port = port
        self.target = target
        self.status = 'unknown'

        self.timeout = 5

    def __connect(self):
        try:
            rpc_transport = transport.DCERPCTransportFactory(
                'ncacn_np:%s[\\pipe\\browser]' % self.target)

            if self.timeout:
                rpc_transport.set_connect_timeout(self.timeout)

            # Get the DCE RPC object
            self.__dce = rpc_transport.get_dce_rpc()
            self.__dce.connect()

            # Bind
            MSRPC_UUID_SRVSVC = uuidtup_to_bin(
                ('4B324FC8-1670-01D3-1278-5A47BF6EE188', '3.0'))
            self.__dce.bind(MSRPC_UUID_SRVSVC)

        except Exception as e:
            raise Exception('%s' % e)

    def __compare(self):
        try:

            path1 = '\\%s\\..\\%s' % ('A'*39, "n")
            path2 = '\\%s' % "n"

            # See: https://learn.microsoft.com/fr-fr/openspecs/windows_protocols/ms-srvs/2b9b4b27-cef4-4f13-b9e7-f63f6261d709
            request = srvs.NetprPathCompare()
            request['ServerName'] = "%s\x00" % self.target
            request['PathName1'] = path1 + '\x00'
            request['PathName2'] = path2 + '\x00'
            request['PathType'] = 1
            request['Flags'] = 0

            response = self.__dce.request(request)

            self.__vulnerable = struct.pack('<L', 0)

            # The target is vulnerable if the NetprPathCompare response field
            # 'Windows Error' is WERR_OK (0x00000000)
            if response.getData() == self.__vulnerable:
                self.status = 'VULNERABLE'
            else:
                self.status = 'not vulnerable'

        except Exception as e:
            raise Exception('%s' % e)

    def run(self):
        self.__connect()
        self.__compare()
        print("%s:%s" % (self.target, self.status))


# MAIN
if __name__ == '__main__':
    CMDLINE = True

    usage = '%s [option] {-t <target>|-l <iplist.txt>}' % sys.argv[0]
    parser = OptionParser(usage=usage, version='0.4')
    targets = set()

    # Create command line options
    try:
        parser.add_option('-d', dest='descr', action='store_true',
                          help='show description and exit')

        parser.add_option('-t', dest='target', help='target IP or hostname')

        parser.add_option('-l', dest='list',
                          help='text file with list of targets')

        parser.add_option('-s', dest='silent',
                          action='store_true', help='be silent')

        (args, _) = parser.parse_args()

        if not args.descr and not args.target and not args.list:
            print(usage)
            sys.exit(1)

    except (OptionError, TypeError) as e:
        parser.error(e)

    descr = args.descr
    target = args.target
    tList = args.list

    SILENT = args.silent

    if descr:
        print(__doc__)
        sys.exit(0)

    if tList:
        try:
            fd = open(tList, 'r')
        except IOError:
            print('ERROR: unable to read targets list file \'%s\'' % tList)
            sys.exit(1)

        for line in fd.readlines():
            target = line.replace('\n', '').replace('\r', '')
            targets.add(target)
    else:
        targets.add(target)

    if not targets:
        print('ERROR: no targets specified')
        sys.exit(1)

    targets = list(targets)
    targets.sort()

    if not SILENT:
        print()
        print('***********************************************************************')
        print('* On Windows XP SP2 and SP3 this check might lead to a race condition *')
        print('* and heap corruption in the svchost.exe process, but it may not      *')
        print('* crash the service immediately, it can trigger later on inside any   *')
        print('* of the shared services in the process.                              *')
        print('***********************************************************************')
        print()
        answer = input('Do you want to continue? [Y/n] ')

        if answer and answer[0].lower() != 'y':
            sys.exit(1)

    for target in targets:
        current = MS08_067(target)
        current.run()
