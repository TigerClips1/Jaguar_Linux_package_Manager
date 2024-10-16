scdocs-y += \
	ps4-cache.5 \
	ps4-keys.5 \
	ps4-package.5 \
	ps4-repositories.5 \
	ps4-v2.5 \
	ps4-v3.5 \
	ps4-world.5 \
	ps4.8 \
	ps4-adbdump.8 \
	ps4-adbgen.8 \
	ps4-adbsign.8 \
	ps4-add.8 \
	ps4-audit.8 \
	ps4-cache.8 \
	ps4-convndx.8 \
	ps4-convdb.8 \
	ps4-del.8 \
	ps4-dot.8 \
	ps4-extract.8 \
	ps4-fetch.8 \
	ps4-fix.8 \
	ps4-index.8 \
	ps4-info.8 \
	ps4-list.8 \
	ps4-manifest.8 \
	ps4-mkndx.8 \
	ps4-mkpkg.8 \
	ps4-policy.8 \
	ps4-stats.8 \
	ps4-update.8 \
	ps4-upgrade.8 \
	ps4-verify.8 \
	ps4-version.8

install:
	for page in $(scdocs-y); do \
		section=$${page#*.}; \
		$(INSTALLDIR) $(DESTDIR)$(MANDIR)/man$$section; \
		$(INSTALL) $(obj)/$$page $(DESTDIR)$(MANDIR)/man$$section/; \
	done
