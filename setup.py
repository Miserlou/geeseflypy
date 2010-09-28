from distutils.core import setup

setup(
    name='geeseflypy',
    version='0.4',
    author='Jonathan Bowman',
    author_email="bowmanjd@gmail.com",
    url='http://code.google.com/p/geeseflypy/',
    packages=['geesefly',],
    license='Apache License, Version 2.0',
    description='Pure Python implementation of Skein and Threefish',
    long_description=open('README.txt').read(),
    classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: Apache Software License',
    'Operating System :: OS Independent', 
    'Programming Language :: Python :: 2.5',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 3',
    'Topic :: Security :: Cryptography',
    ],
)

