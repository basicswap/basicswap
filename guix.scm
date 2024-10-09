(define-module (guix)
#:use-module (guix packages)
#:use-module ((guix licenses) #:prefix license:)
#:use-module (guix build-system python)
#:use-module (guix build-system pyproject)
#:use-module (guix build-system gnu)
#:use-module (guix git-download)
#:use-module (guix download)
#:use-module (guix search-paths)
#:use-module (gnu packages)
#:use-module (gnu packages pkg-config)
#:use-module (gnu packages autotools)
#:use-module (gnu packages certs)
#:use-module (gnu packages check)
#:use-module (gnu packages cmake)
#:use-module (gnu packages databases)
#:use-module (gnu packages finance)
#:use-module (gnu packages gnupg)
#:use-module (gnu packages python)
#:use-module (gnu packages python-build)
#:use-module (gnu packages python-check)
#:use-module (gnu packages python-crypto)
#:use-module (gnu packages python-science)
#:use-module (gnu packages python-xyz)
#:use-module (gnu packages libffi)
#:use-module (gnu packages license))


(define libsecp256k1-basicswap
  (package
    (name "libsecp256k1-basicswap")
    (version "basicswap_v0.2")
    (source (origin
      (method git-fetch)
      (uri (git-reference
        (url "https://github.com/basicswap/secp256k1")
        (commit version)))
      (sha256
       (base32
        "0zvqgswmy1q46nmpjn388pljvl65x3y2k4caw742m3j121jqmfgx"))
      (file-name (git-file-name name version))))
    (build-system gnu-build-system)
    (arguments
     '(#:configure-flags '("--enable-shared"
                           "--disable-dependency-tracking"
                           "--with-pic"
                           "--enable-module-extrakeys"
                           "--enable-module-recovery"
                           "--enable-module-schnorrsig"
                           "--enable-experimental"
                           "--enable-module-ecdh"
                           "--enable-benchmark=no"
                           "--enable-tests=no"
                           "--enable-module-ed25519"
                           "--enable-module-generator"
                           "--enable-module-dleag"
                           "--enable-module-ecdsaotves"
                           "--with-valgrind=no"
                           )))
    (native-inputs
     (list autoconf automake libtool))
    (synopsis "C library for EC operations on curve secp256k1")
    (description
     "Optimized C library for EC operations on curve secp256k1.\n")
    (home-page "https://github.com/bitcoin-core/secp256k1")
    (license license:unlicense)))


(define python-coincurve-basicswap
  (package
    (name "python-coincurve-basicswap")
    (version "basicswap_v0.2")
    (source
     (origin
       (method git-fetch)
       (uri
        (git-reference
         (url "https://github.com/basicswap/coincurve")
         (commit version)))
       (file-name
        (git-file-name name version))
       (sha256
        (base32 "1vm9cvwr0z02zc0mp7l8qj9vhg8kmfrzysiwzg91zkgmccza9ryc"))))
    (build-system pyproject-build-system)
    (arguments
     `(#:phases
       (modify-phases %standard-phases
         (add-before 'build 'set-version
           (lambda _
             (setenv "COINCURVE_IGNORE_SYSTEM_LIB" "OFF")
             ;; ZIP does not support timestamps before 1980.
             (setenv "SOURCE_DATE_EPOCH" "315532800")))
         )))
    (propagated-inputs
     (list
      libsecp256k1-basicswap
      python-asn1crypto
      python-cffi))
    (native-inputs
     (list
      cmake-3.30
      python-hatchling
      python-scikit-build
      python-scikit-build-core
      pkg-config
      python-pytest
      python-pytest-benchmark
      ))
    (synopsis "Python libsecp256k1 wrapper")
    (description "Python libsecp256k1 wrapper.")
    (home-page "https://github.com/basicswap/coincurve")
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
  (version "0.13.5")
  (source (origin
    (method git-fetch)
    (uri (git-reference
      (url "https://github.com/basicswap/basicswap")
      (commit "25b479fdb683bfc0261e3378589c3282b51b122a")))
    (sha256
      (base32
        "153awdqh7wpmc8xs6yvf3na63b84zpkfnhan3ni2bjb9y691yl24"))
    (file-name (git-file-name name version))))
  (build-system python-build-system)

  (native-search-paths (list $SSL_CERT_DIR $SSL_CERT_FILE))
  (arguments
     '(#:tests? #f ; TODO: Add coin binaries
       #:phases (modify-phases %standard-phases
                  (add-after 'unpack 'patch-env
                    (lambda* (#:key inputs #:allow-other-keys)
                      (substitute* "basicswap/bin/prepare.py"
                        (("GUIX_SSL_CERT_DIR = None")
                         (string-append "GUIX_SSL_CERT_DIR = \"" (search-input-directory inputs "etc/ssl/certs") "\""))))))))
  (propagated-inputs
   (list
    gnupg
    nss-certs
    python-coincurve-basicswap
    python-pycryptodome
    python-pytest
    python-sqlalchemy-1.4.39
    python-pyzmq
    python-gnupg
    python-jinja2
    python-pysocks))
  (native-inputs
   (list
    python-wheel
    python-pylint
    python-pyflakes))
  (synopsis "Simple Atomic Swap Network - Proof of Concept")
  (description "Facilitates cross-chain atomic swaps")
  (home-page "https://github.com/basicswap/basicswap")
  (license license:bsd-3)))
