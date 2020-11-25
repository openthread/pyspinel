#!/usr/bin/env python3
#
#  Copyright (c) 2016-2017, The OpenThread Authors.
#  All rights reserved.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#
from setuptools import setup, find_packages
from setuptools.command import install
import shutil
import os
import sys


class _InstallCommand(install.install):
    user_options = install.install.user_options + [
        ('extcap-path=', None, 'Path to Wireshark extcap directory'),
    ]

    def __init__(self, *args, **kwargs):
        super(_InstallCommand, self).__init__(*args, **kwargs)
        self.extcap_path = None

    def run(self):
        if self.extcap_path:
            _copy_script('extcap_ot.py', self.extcap_path)
            if sys.platform == 'win32':
                _copy_script('extcap_ot.bat', self.extcap_path)
        else:
            print('WARNING: Wireshark extcap is not installed. To install:',
                  file=sys.stderr)
            print(
                '1. Get Wireshark extcap path from Wireshark -> About -> Folders -> Extcap path',
                file=sys.stderr)
            print(
                '2. Run setup.py with --extcap-path=<extcap path> if you are installing by executing setup.py',
                file=sys.stderr)
            print('   or', file=sys.stderr)
            print(
                '   Provide --install-option="--extcap-path=<extcap path>" if you are installing by pip',
                file=sys.stderr)
        super(_InstallCommand, self).run()


def _copy_script(src, dest):
    cwd = os.path.abspath(os.path.dirname(__file__))
    src = os.path.join(cwd, src)
    print(f'copying {src} -> {dest}')
    shutil.copy2(src, dest)


setup(
    name='pyspinel',
    version='1.0.3',
    description=
    'A Python interface to the OpenThread Network Co-Processor (NCP)',
    url='https://github.com/openthread/openthread',
    author='The OpenThread Authors',
    author_email='openthread-users@googlegroups.com',
    license='BSD',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Operating System :: MacOS',
        'Operating System :: POSIX :: Linux',
        'License :: OSI Approved :: BSD License',
        'Topic :: System :: Networking',
        'Topic :: System :: Hardware :: Hardware Drivers',
        'Topic :: Software Development :: Embedded Systems',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='openthread thread spinel ncp',
    packages=find_packages(),
    install_requires=[
        'pyserial',
        'ipaddress;python_version<"3.3"',
    ],
    scripts=['spinel-cli.py', 'sniffer.py', 'extcap_ot.py', 'extcap_ot.bat'],
    cmdclass={'install': _InstallCommand},
)
