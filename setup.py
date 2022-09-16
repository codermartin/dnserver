import sys

sys.stderr.write(
    """
===============================
Unsupported installation method
===============================
dnserver does not supports installation with `python setup.py install`.
Please use `python -m pip install .` instead.
"""
)
sys.exit(1)


# The below code will never execute, however GitHub is particularly
# picky about where it finds Python packaging metadata.
# See: https://github.com/github/feedback/discussions/6456
#
# To be removed once GitHub catches up.

setup(
    name='dnserver',
    install_requires=[
        'dnslib>=0.9.20',
        'tomli;python_version<"3.11"',
        'typing_extensions;python_version<"3.8"',
    ],
)
