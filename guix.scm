(define-module (guix)
#:use-module (guix packages)
#:use-module ((guix licenses) #:prefix license:)
#:use-module (guix build-system python)
#:use-module (guix build-system gnu)
#:use-module (guix git-download)
#:use-module (guix download)
#:use-module (guix search-paths)
#:use-module (gnu packages)
#:use-module (gnu packages pkg-config)
#:use-module (gnu packages autotools)
#:use-module (gnu packages certs)
#:use-module (gnu packages check)
#:use-module (gnu packages databases)
#:use-module (gnu packages finance)
#:use-module (gnu packages gnupg)
#:use-module (gnu packages protobuf)
#:use-module (gnu packages python)
#:use-module (gnu packages python-build)
#:use-module (gnu packages python-crypto)
#:use-module (gnu packages python-xyz)
#:use-module (gnu packages libffi)
#:use-module (gnu packages license))


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

(define-public basicswap
(package
  (name "basicswap")
  (version "0.11.58")
  (source (origin
    (method git-fetch)
    (uri (git-reference
      (url "https://github.com/tecnovert/basicswap")
      (commit "9729dcf526917eb5e128dd72b091464d1e72fe54")))
    (sha256
      (base32
        "0sjxk4c9vzn5fr8dqxrmvgw1267njjkblajxvqf3kls5b2s7l41k"))
    (file-name (git-file-name name version))))
  (build-system python-build-system)

  (native-search-paths (list $SSL_CERT_DIR $SSL_CERT_FILE))
  (arguments
     '(#:tests? #f ; TODO: Add coin binaries
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'patch-env
                    (lambda* (#:key inputs #:allow-other-keys)
                      (substitute* "bin/basicswap_prepare.py"
                        (("GUIX_SSL_CERT_DIR = None")
                         (string-append "GUIX_SSL_CERT_DIR = \"" (search-input-directory inputs "etc/ssl/certs") "\"")))
                        )
                        ))))
  (propagated-inputs
   (list
    gnupg
    nss-certs
    python-coincurve-anonswap
    python-pycryptodome
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
    python-wheel
    python-pylint
    python-pyflakes
    ))
  (synopsis "Simple Atomic Swap Network - Proof of Concept")
  (description #f)
  (home-page "https://github.com/tecnovert/basicswap")
  (license license:bsd-3)))
