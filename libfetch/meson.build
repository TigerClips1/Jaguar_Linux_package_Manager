libfetch_src = [
	'common.c',
	'fetch.c',
	'file.c',
	'http.c',
	'openssl-compat.c'
]

errlist_generator = find_program('errlist.sh')

httperr_h = custom_target(
	'httpderr.h',
	capture: true,
	command: [errlist_generator, 'http_errlist', 'HTTP', '@INPUT@'],
	output: 'httperr.h',
	input: 'http.errors',
)

libfetch_src += [httperr_h]

libfetch_cargs = [
	'-DCA_CERT_FILE="/' + ps4_confdir / 'ca.pem"',
	'-DCA_CRL_FILE="/' + ps4_confdir / 'crl.pem"',
	'-DCLIENT_CERT_FILE="/' + ps4_confdir / 'cert.pem"',
	'-DCLIENT_KEY_FILE="/' + ps4_confdir / 'cert.key"',
]

libfetch = static_library(
	'fetch',
	libfetch_src,
	c_args: libfetch_cargs,
	dependencies: [
		libportability_dep.partial_dependency(compile_args: true, includes: true),
		crypto_dep.partial_dependency(compile_args: true, includes: true)
	],
)

libfetch_dep = declare_dependency(
	link_whole: libfetch,
	include_directories: include_directories('.'),
)
