man_filenames = [
    'ps4.8.scd',
    'ps4-adbdump.8.scd',
    'ps4-adbgen.8.scd',
    'ps4-adbsign.8.scd',
    'ps4-add.8.scd',
    'ps4-audit.8.scd',
    'ps4-cache.5.scd',
    'ps4-cache.8.scd',
    'ps4-convdb.8.scd',
    'ps4-convndx.8.scd',
    'ps4-del.8.scd',
    'ps4-dot.8.scd',
    'ps4-extract.8.scd',
    'ps4-fetch.8.scd',
    'ps4-fix.8.scd',
    'ps4-index.8.scd',
    'ps4-info.8.scd',
    'ps4-keys.5.scd',
    'ps4-list.8.scd',
    'ps4-manifest.8.scd',
    'ps4-mkndx.8.scd',
    'ps4-mkpkg.8.scd',
    'ps4-package.5.scd',
    'ps4-policy.8.scd',
    'ps4-repositories.5.scd',
    'ps4-search.8.scd',
    'ps4-stats.8.scd',
    'ps4-update.8.scd',
    'ps4-upgrade.8.scd',
    'ps4-v2.5.scd',
    'ps4-v3.5.scd',
    'ps4-verify.8.scd',
    'ps4-version.8.scd',
    'ps4-world.5.scd',
]
man_files = files(man_filenames)

if scdoc_dep.found()
    scdoc_prog = find_program(scdoc_dep.get_variable(pkgconfig: 'scdoc'), native: true)
    sh = find_program('sh', native: true)
    mandir = get_option('mandir')

    foreach filename : man_filenames
        topic = '@0@'.format(filename).split('.')[-3].split('/')[-1]
        section = '@0@'.format(filename).split('.')[-2]
        output = '@0@.@1@'.format(topic, section)

        custom_target(
            output,
            input: files(filename),
            capture: true,
            output: output,
            command: [
                sh, '-c', '@0@ < @INPUT@'.format(scdoc_prog.full_path())
            ],
            install: true,
            install_dir: '@0@/man@1@'.format(mandir, section)
        )
    endforeach
endif
