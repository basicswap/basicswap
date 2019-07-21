import setuptools
import re
import io

__version__ = re.search(
    r'__version__\s*=\s*[\'"]([^\'"]*)[\'"]',
    io.open('basicswap/__init__.py', encoding='utf_8_sig').read()
).group(1)

setuptools.setup(
    name="basicswap",
    version=__version__,
    author="tecnovert",
    author_email="hello@particl.io",
    description="Particl atomic swap demo",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/tecnovert/basicswap",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
    install_requires=[
        "pyzmq",
        "protobuf",
        "sqlalchemy",
        "python-gnupg",
    ],
    entry_points={
        "console_scripts": [
            "basicswap-run=bin.basicswap_run:main",
        ]
    },
    test_suite="tests.test_suite"
)
