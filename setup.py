from distutils.core import setup

VERSION = '0.1.0'

setup(
    name='bsa',
    version=VERSION,
    description="Bind Status Analyzer",
    long_description="""
    A tool that supplies programmatic access to bind databases.
    """,
    author='John-John Tedro',
    author_email='johnjohn.tedro@gmail.com',
    url='http://github.com/udoprog/bsa',
    license='GPLv3',
    packages=[
        'bsa',
        'bsa.suites'
    ],
    requires=[
        "ipaddr",
        "pyparsing",
    ],
    scripts=['bin/bsa'],
)
