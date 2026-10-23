package=zeromq
$(package)_version=4.3.5
$(package)_download_path=https://github.com/zeromq/libzmq/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=6653ef5910f17954861fe72332e68b03ca6e4d9c7160eb3a8de5a5a913bfab43
$(package)_patches=0001-fix-build-with-older-mingw64.patch 0002-no-pthread-setname-on-mingw.patch

define $(package)_set_vars
  # --disable-Werror: libzmq turns its own warnings into errors, and exempts
  # itself only when it detects it is building ON OSX. Cross-compiling for
  # darwin from Linux defeats that detection, so the old clang in the darwin
  # toolchain fails the build on -Wmissing-braces in src/proxy.cpp.
  # The warnings are in libzmq itself.
  $(package)_config_opts=--without-docs --disable-shared --without-libsodium --disable-curve --disable-curve-keygen --disable-perf --disable-drafts --disable-libunwind --disable-libbsd --without-pgm --without-norm --without-vmci --without-nss --disable-Werror
  $(package)_config_opts_linux=--with-pic
  $(package)_cxxflags=-std=c++11
endef

define $(package)_preprocess_cmds
   patch -p1 < $($(package)_patch_dir)/0001-fix-build-with-older-mingw64.patch && \
   patch -p1 < $($(package)_patch_dir)/0002-no-pthread-setname-on-mingw.patch && \
  ./autogen.sh
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) src/libzmq.la
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-libLTLIBRARIES install-includeHEADERS install-pkgconfigDATA
endef

define $(package)_postprocess_cmds
  sed -i.old "s/ -lstdc++//" lib/pkgconfig/libzmq.pc && \
  rm -rf bin share
endef
