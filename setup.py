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
    author_email="tecnovert@tecnovert.net",
    description="Simple atomic swap system",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/tecnovert/basicswap",
    packages=setuptools.find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Linux",
    ],
    keywords=[
        "crypto",
        "cryptocurrency",
        "particl",
        "bitcoin",
        "monero",
    ],
    install_requires=[
        "wheel",
        "pyzmq",
        "protobuf",
        "sqlalchemy==1.4.39",
        "python-gnupg",
        "Jinja2",
        "pycryptodome",
        "PySocks",
        "mnemonic",
    ],
    entry_points={
        "console_scripts": [
            "basicswap-run=bin.basicswap_run:main",
            "basicswap-prepare=bin.basicswap_prepare:main",
        ]
    }
)
