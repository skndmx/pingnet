from setuptools import find_packages, setup
setup(
    name='pingnet',
    packages=find_packages(),
    entry_points={
          'console_scripts': ['pingnet=src.pingnet:main',],
    },
)