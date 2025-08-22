from setuptools import setup, find_packages
import os

packages = find_packages(include=['squashfs', 'squashfs.*'])

setup(
    name='squashfs-parser',
    version='0.0.1',
    packages=packages,
    install_requires=[
        'lz4', 'zstandard', 'hexdump'
    ],
)