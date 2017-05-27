#!/usr/bin/env python

from distutils.core import setup

setup(
    name='llmnr_multihost',
    version='1.0',
    description='LLMNR dual stack multihost listener and publisher',
    author='Vitaly Greck',
    author_email='vintozver@ya.ru',
    url='https://www.python.org/sigs/distutils-sig/',
    packages=['llmnr_multihost'],
    install_requires=[
        'netifaces',
        'dnslib',
    ],
    entry_points={
        'console_scripts': [
            'llmnr_multihost=llmnr_multihost.run:main',
        ],
    },
)