# -*- coding: utf-8 -*-
#
# NetPyntest
#
# Copyright (c) Alejandro Espinosa Alvarez - a.espinosa.alvarez@gmail.com
# Project home: https://github.com/aespinosaalvarez/NetPyntest
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
# following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
# following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
# following disclaimer in the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from os.path import dirname, join
from setuptools import setup, find_packages

# Import requirements
with open(join(dirname(__file__), 'requirements.txt')) as f:
    required = f.read().splitlines()


setup(
    name='NetPyntest',
    version='1.0.0',
    install_requires=required,
    url='https://github.com/aespinosaalvarez/NetPyntest',
    license='FreeBSD',
    author='Alejandro Espinosa Alvarez',
    author_email='a.espinosa.alvarez@gmail.com',
    packages=find_packages(),
    include_package_data=True,
    entry_points={'console_scripts': [
        'netpyntest = netpyntest_lib.netpyntest:main',
        ]},
    description='Network Pentesting Tool',
    long_description=open('README.md', "r").read(),
    classifiers=[
        'Environment :: Console',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: BSD License',
        'Operating System :: MacOS',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        ]
)
