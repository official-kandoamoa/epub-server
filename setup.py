#!/usr/bin/env python3
from setuptools import setup

setup(
    name='epub-server',
    version='1.0.0',
    description='Serve an EPUB as a local website so you can read it in a browser',
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author='KandoaMoa',
    url='https://github.com/official-kandoamoa/epub-server',
    py_modules=['epub_server'],
    entry_points={
        'console_scripts': [
            'epub-server=epub_server:main',
        ],
    },
    python_requires='>=3.7',
    classifiers=[
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Topic :: Multimedia :: Graphics :: Viewers',
    ],
)
