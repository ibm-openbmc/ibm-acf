project('pam_wrapper', 'c', version: '1.0', meson_version: '>=0.53.2')
ldl = declare_dependency(link_args: ['-ldl'])

#Need location of pam library for header file
r = run_command('./getliblocation.sh', 'libpam')
if r.returncode() != 0
    message('could not find libpam, using predefined location')
    pamlocstr = '/usr/lib/x86_64-linux-gnu/libpam.so'
else
    output = r.stdout().strip()
    pamlocstr = '"' + output + '"'
endif

cdata = configuration_data(
    {
        'version' : '"1.2.3"',
        'PACKAGE' : '"pam_wrapper"',
        'HAVE_SECURITY_PAM_APPL_H': '1',
        'HAVE_SECURITY_PAM_MODULES_H' : '1',
        'HAVE_SECURITY_PAM_EXT_H': '1',
        'PAM_LIBRARY': pamlocstr,
        '_XOPEN_SOURCE' : '700',
    },
)

configure_file(output: 'config.h', configuration: cdata)
configuration_inc = include_directories(['.', './include'])
cxx = meson.get_compiler('c')
inc_dir = configuration_inc
pam = cxx.find_library('pam', required: true)
deps = [pam, ldl]

pam_wrapper_lib = library(
    'pam_wrapper',
    'src/pam_wrapper.c',
    dependencies: deps,
    include_directories: configuration_inc,
)
pamtest_lib = library(
    'pamtest',
    'src/libpamtest.c',
    dependencies: deps,
    include_directories: configuration_inc,
)

lib_pam_wrapper_dep = declare_dependency(
    dependencies: deps,
    include_directories: inc_dir,
    link_with: [pam_wrapper_lib, pamtest_lib],
)
