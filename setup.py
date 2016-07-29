import os
import sys
from setuptools import setup

# Set external files
#try:
#    from pypandoc import convert
#    README = convert('README.md', 'rst')     
#except ImportError:
#    README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()
#
#with open(os.path.join(os.path.dirname(__file__), 'requirements.txt')) as f:
#    required = f.read().splitlines()
#
#with open(os.path.join(os.path.dirname(__file__), 'test_requirements.txt')) as f:
#    test_required = f.read().splitlines()

setup(
    name='geesefly',
    version='0.4',
    author='Jonathan Bowman',
    author_email="bowmanjd@gmail.com",
    url='http://code.google.com/p/geeseflypy/',
    packages=['geesefly',],
    license='Apache License, Version 2.0',
    description='Pure Python implementation of Skein and Threefish',
    long_description=open('README.md').read(),
    classifiers=[
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Intended Audience :: Information Technology",
    "Intended Audience :: Science/Research",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: OS Independent", 
    "Programming Language :: Python :: 2.5",
    "Programming Language :: Python :: 2.6",
    "Programming Language :: Python :: 2.7",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.0",
    "Programming Language :: Python :: 3.1",
    "Topic :: Security :: Cryptography",
    ],
)
