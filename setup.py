from setuptools import find_packages, setup
from src import __version__
setup(
    name='pingnet',
    packages=find_packages(),
    version = __version__,
    entry_points={
          'console_scripts': ['pingnet=src.pingnet:main',],
    },
)