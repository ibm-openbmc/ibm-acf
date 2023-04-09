tacf_files = files('tacf.hpp',
                   'tacfCelogin.hpp',
                   'tacfDbus.hpp',
                   'tacfSpw.hpp',
                   'targetedAcf.hpp')

tacf_dep = declare_dependency(sources : tacf_files, include_directories :  incdir)

pkg_mod = import('pkgconfig').generate(libraries: tacf_dep,
                                       name : 'tacf',
                                       subdirs : 'tacf',
                                       version : '1.0',
                                       description : 'IBM Targeted ACF support')

install_headers(tacf_files, subdir : 'tacf')
