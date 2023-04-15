# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

DIST_SUBDIRS = secp256k1 univalue

AM_LDFLAGS = $(PTHREAD_CFLAGS) $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS) $(ERROR_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

DRIVECHAIN_INCLUDES=-I$(builddir) $(BDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(LEVELDB_CPPFLAGS) $(CRYPTO_CFLAGS) $(SSL_CFLAGS)

DRIVECHAIN_INCLUDES += -I$(srcdir)/secp256k1/include
DRIVECHAIN_INCLUDES += $(UNIVALUE_CFLAGS)

LIBDRIVECHAIN_SERVER=libskydoge_server.a
LIBDRIVECHAIN_COMMON=libskydoge_common.a
LIBDRIVECHAIN_CONSENSUS=libskydoge_consensus.a
LIBDRIVECHAIN_CLI=libskydoge_cli.a
LIBDRIVECHAIN_UTIL=libskydoge_util.a
LIBDRIVECHAIN_CRYPTO=crypto/libskydoge_crypto.a
LIBDRIVECHAINQT=qt/libskydogeqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la

if ENABLE_ZMQ
LIBDRIVECHAIN_ZMQ=libskydoge_zmq.a
endif
if BUILD_DRIVECHAIN_LIBS
LIBDRIVECHAINCONSENSUS=libskydogeconsensus.la
endif
if ENABLE_WALLET
LIBDRIVECHAIN_WALLET=libskydoge_wallet.a
endif

$(LIBSECP256K1): $(wildcard secp256k1/src/*) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBDRIVECHAIN_CRYPTO) \
  $(LIBDRIVECHAIN_UTIL) \
  $(LIBDRIVECHAIN_COMMON) \
  $(LIBDRIVECHAIN_CONSENSUS) \
  $(LIBDRIVECHAIN_SERVER) \
  $(LIBDRIVECHAIN_CLI) \
  $(LIBDRIVECHAIN_WALLET) \
  $(LIBDRIVECHAIN_ZMQ)

lib_LTLIBRARIES = $(LIBDRIVECHAINCONSENSUS)

bin_PROGRAMS =
noinst_PROGRAMS =
TESTS =
BENCHMARKS =

if BUILD_DRIVECHAIND
  bin_PROGRAMS += skydoged
endif

if BUILD_DRIVECHAIN_UTILS
  bin_PROGRAMS += skydoge-cli skydoge-tx
endif

.PHONY: FORCE check-symbols check-security
# skydoge core #

DRIVECHAIN_CORE_H = \
  addressbook.h \
  addrdb.h \
  addrman.h \
  apiclient.h \
  base58.h \
  bech32.h \
  bip39words.h \
  bloom.h \
  blockencodings.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkpoints.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  compat.h \
  compat/byteswap.h \
  compat/endian.h \
  compat/sanity.h \
  compressor.h \
  consensus/consensus.h \
  consensus/tx_verify.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  fs.h \
  httprpc.h \
  httpserver.h \
  indirectmap.h \
  init.h \
  key.h \
  keystore.h \
  dbwrapper.h \
  limitedmap.h \
  memusage.h \
  merkleblock.h \
  miner.h \
  net.h \
  net_processing.h \
  netaddress.h \
  netbase.h \
  netmessagemaker.h \
  noui.h \
  policy/feerate.h \
  policy/fees.h \
  policy/policy.h \
  policy/rbf.h \
  pow.h \
  protocol.h \
  random.h \
  reverse_iterator.h \
  reverselock.h \
  rpc/blockchain.h \
  rpc/client.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/safemode.h \
  rpc/server.h \
  rpc/register.h \
  rpc/util.h \
  scheduler.h \
  script/sigcache.h \
  script/sign.h \
  script/standard.h \
  script/ismine.h \
  sidechain.h \
  sidechaindb.h \
  streams.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  threadinterrupt.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  ui_interface.h \
  undo.h \
  util.h \
  utilmoneystr.h \
  utiltime.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/coincontrol.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/init.h \
  wallet/rpcwallet.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/walletutil.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqconfig.h\
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	@$(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"
libskydoge_util_a-clientversion.$(OBJEXT): obj/build.h

# server: shared between skydoged and skydoge-qt
libskydoge_server_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) $(MINIUPNPC_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS) -fPIC
libskydoge_server_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
libskydoge_server_a_SOURCES = \
  addressbook.cpp \
  addrdb.cpp \
  addrman.cpp \
  apiclient.cpp \
  bloom.cpp \
  blockencodings.cpp \
  chain.cpp \
  checkpoints.cpp \
  consensus/tx_verify.cpp \
  httprpc.cpp \
  httpserver.cpp \
  init.cpp \
  dbwrapper.cpp \
  merkleblock.cpp \
  miner.cpp \
  net.cpp \
  net_processing.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/policy.cpp \
  policy/rbf.cpp \
  pow.cpp \
  rest.cpp \
  rpc/blockchain.cpp \
  rpc/mining.cpp \
  rpc/misc.cpp \
  rpc/net.cpp \
  rpc/rawtransaction.cpp \
  rpc/safemode.cpp \
  rpc/server.cpp \
  script/sigcache.cpp \
  script/ismine.cpp \
  sidechain.cpp \
  sidechaindb.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  ui_interface.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(DRIVECHAIN_CORE_H)

if ENABLE_ZMQ
libskydoge_zmq_a_CPPFLAGS = $(DRIVECHAIN_INCLUDES) $(ZMQ_CFLAGS)
libskydoge_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libskydoge_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp
endif


# wallet: shared between skydoged and skydoge-qt, but only linked
# when wallet enabled
libskydoge_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES)  -fPIC
libskydoge_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC  
libskydoge_wallet_a_SOURCES = \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/init.cpp \
  wallet/rpcdump.cpp \
  wallet/rpcwallet.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  $(DRIVECHAIN_CORE_H)

# crypto primitives library
crypto_libskydoge_crypto_a_CPPFLAGS = $(AM_CPPFLAGS)-fPIC
crypto_libskydoge_crypto_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
crypto_libskydoge_crypto_a_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/common.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/ripemd160.cpp \
  crypto/aes_helper.c \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/blake.c \
  crypto/bmw.c \
  crypto/cubehash.c \
  crypto/echo.c \
  crypto/fugue.c \
  crypto/groestl.c \
  crypto/hamsi.c \
  crypto/haval.c \
  crypto/jh.c \
  crypto/keccak.c \
  crypto/luffa.c \
  crypto/sph_sha2big.c \
  crypto/shabal.c \
  crypto/shavite.c \
  crypto/simd.c \
  crypto/skein.c \
  crypto/whirlpool.c \
  crypto/sph_blake.h \
  crypto/sph_bmw.h \
  crypto/sph_cubehash.h \
  crypto/sph_echo.h \
  crypto/sph_fugue.h \
  crypto/sph_groestl.h \
  crypto/sph_hamsi.h \
  crypto/sph_haval.h \
  crypto/sph_jh.h \
  crypto/sph_keccak.h \
  crypto/sph_luffa.h \
  crypto/sph_sha2.h \
  crypto/sha2.c \
  crypto/sph_shabal.h \
  crypto/sph_shavite.h \
  crypto/sph_simd.h \
  crypto/sph_skein.h \
  crypto/sph_types.h \
  crypto/sph_whirlpool.h \
  crypto/sph_tiger.h \
  crypto/tiger.cpp \
  crypto/sha512.h

if USE_ASM
crypto_libskydoge_crypto_a_SOURCES += crypto/sha256_sse4.cpp
endif

# consensus: shared between all executables that validate any consensus rules.
libskydoge_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES)
libskydoge_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libskydoge_consensus_a_SOURCES = \
  amount.h \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/skydogeconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  utilstrencodings.cpp \
  utilstrencodings.h \
  version.h

# common: shared between skydoged, and skydoge-qt and non-server tools
libskydoge_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES)
libskydoge_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libskydoge_common_a_SOURCES = \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  compressor.cpp \
  core_read.cpp \
  core_write.cpp \
  key.cpp \
  keystore.cpp \
  netaddress.cpp \
  netbase.cpp \
  policy/feerate.cpp \
  protocol.cpp \
  scheduler.cpp \
  script/sign.cpp \
  script/standard.cpp \
  warnings.cpp \
  $(DRIVECHAIN_CORE_H)

# util: shared between all executables.
# This library *must* be included to make sure that the glibc
# backward-compatibility objects and their sanity checks are linked.
libskydoge_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) -fPIC
libskydoge_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
libskydoge_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  compat/glibc_sanity.cpp \
  compat/glibcxx_sanity.cpp \
  compat/strnlen.cpp \
  fs.cpp \
  random.cpp \
  rpc/protocol.cpp \
  rpc/util.cpp \
  support/cleanse.cpp \
  sync.cpp \
  threadinterrupt.cpp \
  util.cpp \
  utilmoneystr.cpp \
  utilstrencodings.cpp \
  utiltime.cpp \
  $(DRIVECHAIN_CORE_H)

if GLIBC_BACK_COMPAT
libskydoge_util_a_SOURCES += compat/glibc_compat.cpp
endif

# cli: shared between skydoge-cli and skydoge-qt
libskydoge_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) -fPIC
libskydoge_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
libskydoge_cli_a_SOURCES = \
  rpc/client.cpp \
  $(DRIVECHAIN_CORE_H)

nodist_libskydoge_util_a_SOURCES = $(srcdir)/obj/build.h
#

# skydoged binary #
skydoged_SOURCES = skydoged.cpp
skydoged_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) -fPIC
skydoged_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
skydoged_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -fPIC

if TARGET_WINDOWS
skydoged_SOURCES += skydoged-res.rc
endif

skydoged_LDADD = \
  $(LIBDRIVECHAIN_SERVER) \
  $(LIBDRIVECHAIN_COMMON) \
  $(LIBUNIVALUE) \
  $(LIBDRIVECHAIN_UTIL) \
  $(LIBDRIVECHAIN_WALLET) \
  $(LIBDRIVECHAIN_ZMQ) \
  $(LIBDRIVECHAIN_CONSENSUS) \
  $(LIBDRIVECHAIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBLEVELDB_SSE42) \
  $(LIBMEMENV) \
  $(LIBSECP256K1)

skydoged_LDADD += $(BOOST_LIBS) $(BDB_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(MINIUPNPC_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS)

# skydoge-cli binary #
skydoge_cli_SOURCES = skydoge-cli.cpp
skydoge_cli_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) $(EVENT_CFLAGS) -fPIC
skydoge_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
skydoge_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -fPIC

if TARGET_WINDOWS
skydoge_cli_SOURCES += skydoge-cli-res.rc
endif

skydoge_cli_LDADD = \
  $(LIBDRIVECHAIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBDRIVECHAIN_UTIL) \
  $(LIBDRIVECHAIN_CRYPTO)

skydoge_cli_LDADD += $(BOOST_LIBS) $(SSL_LIBS) $(CRYPTO_LIBS) $(EVENT_LIBS)
#

# skydoge-tx binary #
skydoge_tx_SOURCES = skydoge-tx.cpp
skydoge_tx_CPPFLAGS = $(AM_CPPFLAGS) $(DRIVECHAIN_INCLUDES) -fPIC
skydoge_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC
skydoge_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) -fPIC

if TARGET_WINDOWS
skydoge_tx_SOURCES += skydoge-tx-res.rc
endif

skydoge_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBDRIVECHAIN_COMMON) \
  $(LIBDRIVECHAIN_UTIL) \
  $(LIBDRIVECHAIN_CONSENSUS) \
  $(LIBDRIVECHAIN_CRYPTO) \
  $(LIBSECP256K1)

skydoge_tx_LDADD += $(BOOST_LIBS) $(CRYPTO_LIBS)
#

# skydogeconsensus library #
if BUILD_DRIVECHAIN_LIBS
include_HEADERS = script/skydogeconsensus.h
libskydogeconsensus_la_SOURCES = $(crypto_libskydoge_crypto_a_SOURCES) $(libskydoge_consensus_a_SOURCES)

if GLIBC_BACK_COMPAT
  libskydogeconsensus_la_SOURCES += compat/glibc_compat.cpp
endif

libskydogeconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS) -fPIC
libskydogeconsensus_la_LIBADD = $(LIBSECP256K1)
libskydogeconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_DRIVECHAIN_INTERNAL -fPIC
libskydogeconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -fPIC

endif
#

CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

CLEANFILES = $(EXTRA_LIBRARIES)

CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h

EXTRA_DIST = $(CTAES_DIST)


config/skydoge-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/skydoge-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/skydoge-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/skydoge-config.h.in

clean-local:
	-$(MAKE) -C secp256k1 clean
	-$(MAKE) -C univalue clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__

.rc.o:
	@test -f $(WINDRES)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
if GLIBC_BACK_COMPAT
	@echo "Checking glibc back compat..."
	$(AM_V_at) READELF=$(READELF) CPPFILT=$(CPPFILT) $(top_srcdir)/contrib/devtools/symbol-check.py < $(bin_PROGRAMS)
endif

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) READELF=$(READELF) OBJDUMP=$(OBJDUMP) $(top_srcdir)/contrib/devtools/security-check.py < $(bin_PROGRAMS)
endif

%.pb.cc %.pb.h: %.proto
	@test -f $(PROTOC)
	$(AM_V_GEN) $(PROTOC) --cpp_out=$(@D) --proto_path=$(<D) $<

if EMBEDDED_LEVELDB
include Makefile.leveldb.include
endif

if ENABLE_TESTS
include Makefile.test.include
endif

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif
