PKG_CONFIG		?= pkg-config
LUA			?= $(firstword $(wildcard /usr/bin/lua5.3 /usr/bin/lua5.2))

ifeq ($(LUA),no)
LUAPS4			?= no
else ifneq ($(LUA),)
LUAPS4			?= yes
else
$(error Lua interpreter not found. Please specify LUA interpreter, or use LUA=no to build without help.)
endif

ifeq ($(URL_BACKEND),wget)
IO_URL_OBJ		:= io_url_wget.o
else
IO_URL_INCLUDE		:= -Ilibfetch
IO_URL_OBJ		:= io_url_libfetch.o
IO_URL_OBJ_LIBS		:= libfetch/libfetch.a
endif

ifeq ($(CRYPTO),mbedtls)
CRYPTO_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags mbedtls mbedcrypto) -DCRYPTO_USE_MBEDTLS
CRYPTO_LIBS		:= $(shell $(PKG_CONFIG) --libs mbedtls mbedcrypto)
CRYPTO_OBJ		:= crypto_mbedtls.o
else
CRYPTO_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags openssl) -DCRYPTO_USE_OPENSSL
CRYPTO_LIBS		:= $(shell $(PKG_CONFIG) --libs openssl)
CRYPTO_OBJ		:= crypto_openssl.o
endif


ZLIB_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags zlib)
ZLIB_LIBS		:= $(shell $(PKG_CONFIG) --libs zlib)

# Dynamic library
libps4_soname		:= 2.99.0
libps4_so		:= $(obj)/libps4.so.$(libps4_soname)
libps4.so.$(libps4_soname)-objs := \
	adb.o adb_comp.o adb_walk_adb.o adb_walk_genadb.o adb_walk_gentext.o adb_walk_text.o ps4_adb.o \
	atom.o balloc.o blob.o commit.o common.o context.o crypto.o ctype.o database.o hash.o extract_v2.o \
	extract_v3.o fs_fsys.o fs_uvol.o io.o io_gunzip.o tar.o package.o pathbuilder.o print.o \
	solver.o trust.o version.o

libps4.so.$(libps4_soname)-libs :=

ifeq ($(URL_BACKEND),wget)
libps4.so.$(libps4_soname)-objs += io_url_wget.o
else
CFLAGS_ALL += -Ilibfetch
libps4.so.$(libps4_soname)-objs += io_url_libfetch.o
libps4.so.$(libps4_soname)-libs += libfetch/libfetch.a
endif

ifeq ($(CRYPTO),mbedtls)
CRYPTO_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags mbedtls mbedcrypto) -DCRYPTO_USE_MBEDTLS
CRYPTO_LIBS		:= $(shell $(PKG_CONFIG) --libs mbedtls mbedcrypto)
libps4.so.$(libps4_soname)-objs += crypto_mbedtls.o
else
CRYPTO_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags openssl) -DCRYPTO_USE_OPENSSL
CRYPTO_LIBS		:= $(shell $(PKG_CONFIG) --libs openssl)
libps4.so.$(libps4_soname)-objs += crypto_openssl.o
endif

# ZSTD support can be disabled
ifneq ($(ZSTD),no)
ZSTD_CFLAGS		:= $(shell $(PKG_CONFIG) --cflags libzstd)
ZSTD_LIBS		:= $(shell $(PKG_CONFIG) --libs libzstd)
CFLAGS_adb_comp.o	+= -DHAVE_ZSTD
libps4.so.$(libps4_soname)-objs += io_zstd.o
endif

shlibs-y		+= libps4.so.$(libps4_soname)
LDFLAGS_libps4.so.$(libps4_soname) += -Wl,-soname,libps4.so.$(libps4_soname)

install-libps4_so	:= $(INSTALLDIR) $(DESTDIR)$(LIBDIR) && \
			   $(INSTALL) $(libps4_so) $(DESTDIR)$(LIBDIR) && \
			   $(LN) libps4.so.$(libps4_soname) $(DESTDIR)$(LIBDIR)/libps4.so

# Static library
libps4.a-objs		:= $(libps4.so.$(libps4_soname)-objs)
libps4.a-libs		:= $(libps4.so.$(libps4_soname)-libs)

libs-y			+= libps4.a
libps4_a		:= $(obj)/libps4.a

install-libps4_a	:= $(INSTALLDIR) $(DESTDIR)$(LIBDIR) && \
			   $(INSTALL) $(libps4_a) $(DESTDIR)$(LIBDIR)
ps4-static-libs		:= $(libps4.a-libs) $(obj)/libps4.a

# Lua module
ifeq ($(LUAps4),yes)
LUA_VERSION		?= 5.3
LUA_PC			?= lua$(LUA_VERSION)
LUA_LIBDIR		?= /usr/lib/lua/$(LUA_VERSION)
shlibs-y		+= ps4.so
ps4.so-objs		:= lua-ps4.o
CFLAGS_lua-ps4.o	:= -DPS4_VERSION=\"$(VERSION)\" \
			   $(shell $(PKG_CONFIG) $(LUA_PC) --cflags)
ps4lua_so		:= $(obj)/ps4.so
install-ps4lua_so	:= $(INSTALLDIR) $(DESTDIR)$(LUA_LIBDIR) && \
			   $(INSTALL) $(ps4lua_so) $(DESTDIR)$(LUA_LIBDIR)
endif

# ps4 utility
progs-y			+= ps4
ps4-objs		:= \
	ps4.o app_adbdump.o app_adbsign.o app_add.o app_audit.o app_cache.o \
	app_convdb.o app_convndx.o app_del.o app_dot.o app_extract.o app_fetch.o \
	app_fix.o app_index.o app_info.o app_list.o app_manifest.o app_mkndx.o \
	app_mkpkg.o app_policy.o app_update.o app_upgrade.o app_search.o \
	app_stats.o app_verify.o app_version.o app_vertest.o applet.o

LIBS_ps4		:= -lps4
LIBS_ps4-test		:= -lps4
LIBS_ps4.so		:= -L$(obj) -lps4

CFLAGS_ALL		+= -D_ATFILE_SOURCE -Iportability
CFLAGS_ps4.o		:= -DPS4_VERSION=\"$(VERSION)\"
CFLAGS_ps4-static.o	:= -DPS4_VERSION=\"$(VERSION)\" -DOPENSSL_NO_ENGINE
CFLAGS_ps4-test.o	:= -DPS4_VERSION=\"$(VERSION)\" -DOPENSSL_NO_ENGINE -DTEST_MODE

progs-$(STATIC)		+= ps4.static
ps4.static-objs		:= $(filter-out ps4.o,$(ps4-objs)) ps4-static.o
ps4.static-libs		:= $(ps4-static-libs)
LDFLAGS_ps4.static	:= -static
LIBS_ps4.static		:= -Wl,--as-needed -ldl -Wl,--no-as-needed
LDFLAGS_ps4		+= -L$(obj)
LDFLAGS_ps4-test	+= -L$(obj)

CFLAGS_ALL		+= $(CRYPTO_CFLAGS) $(ZLIB_CFLAGS) $(ZSTD_CFLAGS)
LIBS			:= -Wl,--as-needed \
				$(CRYPTO_LIBS) $(ZLIB_LIBS) $(ZSTD_LIBS) \
			   -Wl,--no-as-needed

# Help generation
quiet_cmd_genhelp = GENHELP $@
ifneq ($(LUA),no)
      cmd_genhelp = $(LUA) $(src)/genhelp.lua $(filter %.scd, $^) > $@
else
      cmd_genhelp = echo \\\#define NO_HELP > $@
endif

$(obj)/help.h: $(src)/genhelp.lua $(wildcard doc/ps4*.8.scd) FORCE
	$(call if_changed,genhelp)

CFLAGS_help.o		:= -I$(obj)

generate-y		+= help.h

# Test build
ifeq ($(TEST),y)
progs-y			+= ps4-test
ps4-test-objs		:= ps4-test.o $(filter-out ps4.o, $(ps4-objs))
endif

$(obj)/ps4: $(libps4_so)

$(obj)/ps4-test: $(libps4_so)

$(obj)/ps4.so: $(libps4_so)

generate-y	+= libps4.so

$(obj)/libps4.so:
	$(LN) libps4.so.$(libps4_soname) $(obj)/libps4.so

generate-y	+= ps4.pc

install: $(obj)/ps4 $(libps4_so) $(libps4_a) $(ps4lua_so)
	$(INSTALLDIR) $(DESTDIR)$(SBINDIR)
	$(INSTALL) $(obj)/ps4 $(DESTDIR)$(SBINDIR)
	$(install-libps4_so)
	$(install-libps4_a)
	$(install-ps4lua_so)
	$(INSTALLDIR) $(DESTDIR)$(INCLUDEDIR)/ps4
	$(INSTALL) -m644 src/*.h $(DESTDIR)$(INCLUDEDIR)/ps4
	$(INSTALLDIR) $(DESTDIR)$(PKGCONFIGDIR)
	$(INSTALL) -m644 $(obj)/ps4.pc $(DESTDIR)$(PKGCONFIGDIR)

