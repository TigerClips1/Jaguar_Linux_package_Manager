crypto_backend = get_option('crypto_backend')
url_backend = get_option('url_backend')

libps4_so_version = '2.99.0'
libps4_src = [
	'adb.c',
	'adb_comp.c',
	'adb_walk_adb.c',
	'adb_walk_genadb.c',
	'adb_walk_gentext.c',
	'adb_walk_text.c',
	'ps4_adb.c',
	'atom.c',
	'balloc.c',
	'blob.c',
	'commit.c',
	'common.c',
	'context.c',
	'crypto.c',
        'crypto_@0@.c'.format(crypto_backend),
	'ctype.c',
	'database.c',
	'extract_v2.c',
	'extract_v3.c',
	'fs_fsys.c',
	'fs_uvol.c',
	'hash.c',
	'io.c',
	'io_gunzip.c',
	'io_url_@0@.c'.format(url_backend),
	'package.c',
	'pathbuilder.c',
	'print.c',
	'solver.c',
	'tar.c',
	'trust.c',
	'version.c',
]

libps4_headers = [
	'adb.h',
	'ps4_applet.h',
	'ps4_atom.h',
	'ps4_balloc.h',
	'ps4_blob.h',
	'ps4_context.h',
	'ps4_crypto.h',
        'ps4_crypto_@0@.h'.format(crypto_backend),
	'ps4_ctype.h',
	'ps4_database.h',
	'ps4_defines.h',
	'ps4_extract.h',
	'ps4_fs.h',
	'ps4_hash.h',
	'ps4_io.h',
	'ps4_package.h',
	'ps4_pathbuilder.h',
	'ps4_print.h',
	'ps4_provider_data.h',
	'ps4_solver_data.h',
	'ps4_solver.h',
	'ps4_tar.h',
	'ps4_trust.h',
	'ps4_version.h',
]

ps4_src = [
	'ps4.c',
	'app_adbdump.c',
	'app_adbsign.c',
	'app_add.c',
	'app_audit.c',
	'app_cache.c',
	'app_convdb.c',
	'app_convndx.c',
	'app_del.c',
	'app_dot.c',
	'app_extract.c',
	'app_fetch.c',
	'app_fix.c',
	'app_index.c',
	'app_info.c',
	'app_list.c',
	'app_manifest.c',
	'app_mkndx.c',
	'app_mkpkg.c',
	'app_policy.c',
	'app_update.c',
	'app_upgrade.c',
	'app_search.c',
	'app_stats.c',
	'app_verify.c',
	'app_version.c',
	'app_vertest.c',
	'applet.c',
]

ps4_cargs = [
	'-D_ATFILE_SOURCE',
	'-DPS4_VERSION="' + meson.project_version() + '"',
	'-DCRYPTO_USE_@0@'.format(crypto_backend.to_upper()),
]

if lua_bin.found()
	genhelp_script = files('genhelp.lua')
	genhelp_args = [lua_bin, genhelp_script, '@INPUT@']

	if not get_option('compressed-help')
		genhelp_args += ['--no-zlib']
	endif

	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		input: man_files,
		command: genhelp_args,
	)
else
	generated_help = custom_target(
		'help.h',
		capture: true,
		output: 'help.h',
		command: ['echo', '#define NO_HELP'],
	)
endif

ps4_src += [ generated_help ]

ps4_arch_prefix = get_option('arch_prefix')
if ps4_arch_prefix != ''
	ps4_cargs += ['-DPS4_ARCH_PREFIX="@0@"'.format(ps4_arch_prefix)]
endif

ps4_uvol_db_target = get_option('uvol_db_target').strip('/')
if ps4_uvol_db_target != ''
	ps4_cargs += ['-DPS4_UVOL_DB_TARGET="@0@"'.format(ps4_uvol_db_target)]
endif

if get_option('zstd')
	libps4_src += [ 'io_zstd.c' ]
	ps4_cargs += [ '-DHAVE_ZSTD' ]
endif

libps4_lib = library(
	'ps4',
	libps4_src,
	version: libps4_so_version,
	install: not subproject,
	dependencies: [
		libfetch_dep,
		libportability_dep,
		ps4_deps,
	],
	c_args: ps4_cargs,
)

libps4_dep = declare_dependency(
	link_with: libps4_lib,
)

if not subproject
	pkgc.generate(
		libps4_lib,
		name: 'ps4',
		version: libps4_so_version,
	)

	install_headers(
		libps4_headers,
		subdir: 'ps4',
	)
endif

if(lua_dep.found())
	luaps4_src = [
		'lua-ps4.c',
	]

	libluaps4 = library(
		'luaps4',
		luaps4_src,
		dependencies: [
			lua_dep,
			libps4_dep,
			ps4_deps,
			libportability_dep.partial_dependency(includes: true),
		],
		install: true,
		install_dir: lua_dep.get_variable(pkgconfig: 'libdir'),
		c_args: ps4_cargs,
	)
endif

ps4_exe = executable(
	'ps4',
	ps4_src,
	install: not subproject,
	dependencies: [
		libps4_dep,
		ps4_deps,
		libfetch_dep.partial_dependency(includes: true),
		libportability_dep.partial_dependency(includes: true),
	],
	c_args: ps4_cargs,
)
