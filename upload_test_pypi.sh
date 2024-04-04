#!/bin/bash -e

# remove exisiting dist
rm -rf dist

# re-build package
python3.11 setup.py bdist_wheel sdist

# upload to testpypi
twine upload -r testpypi dist/*