(use-modules
  (guix packages)
  ((guix licenses) #:prefix license:)
  (guix build-system python)
  (guix build-system gnu)
  (guix git-download)
  (guix download)
  (gnu packages)
  (gnu packages pkg-config)
  (gnu packages autotools)
  (gnu packages certs)
  (gnu packages check)
  (gnu packages databases)
  (gnu packages finance)
  (gnu packages gnupg)
  (gnu packages protobuf)
  (gnu packages python)
  (gnu packages python-build)
  (gnu packages python-crypto)
  (gnu packages python-xyz)
  (gnu packages libffi)
  (gnu packages license))

(define libsecp256k1-anonswap
  (package
    (name "libsecp256k1-anonswap")
    (version "anonswap_v0.1")
    (source (origin
      (method git-fetch)
      (uri (git-reference
        (url "https://github.com/tecnovert/secp256k1")
        (commit version)))
      (sha256
       (base32
        "1lrcc5gjywlzvrgwzifva4baa2nsvwr3h0wmkc71q0zhag9pjbah"))
      (file-name (git-file-name name version))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-shared"
                           "--disable-dependency-tracking"
                           "--with-valgrind=no"
                           "--enable-experimental"
                           "--enable-module-recovery"
                           "--enable-module-ecdh"
                           "--enable-benchmark=no"
                           "--enable-tests=no"
                           "--enable-module-ed25519"
                           "--enable-module-generator"
                           "--enable-module-dleag"
                           "--enable-module-ecdsaotves"
                           )))
    (native-inputs
     (list autoconf automake libtool))
    (synopsis "C library for EC operations on curve secp256k1")
    (description
     "Optimized C library for EC operations on curve secp256k1.\n")
    (home-page "https://github.com/bitcoin-core/secp256k1")
    (license license:unlicense)))


(define python-coincurve-anonswap
  (package
    (name "python-coincurve-anonswap")
    (version "anonswap_v0.1")
    (source
     (origin
       (method git-fetch)
       (uri
        (git-reference
         (url "https://github.com/tecnovert/coincurve")
         (commit version)))
       (file-name
        (git-file-name name version))
       (sha256
        (base32 "0vyzvpp2s21js01185qbm1lgs4ps4hki2d6yzprfsjqap1i5qhmp"))))
    (build-system python-build-system)
    (arguments
     '(#:tests? #f ;XXX fails to load "libsecp256k1.dll"
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'patch-libsec256k1-path
                    (lambda _
                      (substitute* "setup.py"
                        (("if has_system_lib\\(\\)")
                         "if True")
                        ((", 'requests'")
                         "")
                        (("download_library\\(self\\)")
                         "")))))))
    (propagated-inputs
     (list
      libsecp256k1-anonswap
      python-asn1crypto
      python-cffi))
    (native-inputs
     (list
      python-setuptools
      pkg-config
      ))
    (synopsis "Python libsecp256k1 wrapper")
    (description "Python libsecp256k1 wrapper.")
    (home-page "https://github.com/tecnovert/coincurve")
    (license license:bsd-3)))

(define python-sqlalchemy-1.4.39
  (package
    (inherit python-sqlalchemy)
    (version "1.4.39")
    (source
      (origin
        (method url-fetch)
        (uri (pypi-uri "SQLAlchemy" version))
        (sha256
          (base32 "09sx2lghywnm7qj1xm8xc3xrgj40bndfh2hbiaq4cfvm71h8k541"))))))

(package
  (name "basicswap")
  (version "0.11.49")
  (source #f)
  (build-system python-build-system)
  (propagated-inputs
   (list
    gnupg
    nss-certs
    python-coincurve-anonswap
    python-pycryptodome
    python-pylint
    python-pyflakes
    python-pytest
    python-protobuf
    python-sqlalchemy-1.4.39
    python-pyzmq
    python-gnupg
    python-jinja2
    python-pysocks
    python-mnemonic
    ))
  (native-inputs
   (list
    python-setuptools
    ))
  (synopsis "Simple Atomic Swap Network - Proof of Concept")
  (description #f)
  (home-page "https://github.com/tecnovert/basicswap")
  (license license:bsd-3))
