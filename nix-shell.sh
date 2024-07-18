#!/bin/sh

# not working
#nix-shell -p python3.pkgs.{wheel,pyzmq,sqlalchemy,python-gnupg,jinja2,pycryptodome,pysocks,coincurve}

nix-shell -E 'with import <nixpkgs> { }; callPackage ./default.nix { }'
