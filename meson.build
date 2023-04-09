project('pam_ibmacf',
        'c' ,
        'cpp',
        default_options : ['cpp_std=c++20'],
        meson_version : '>=0.56.0')

cxx = meson.get_compiler('cpp')

#Dependencies
pam = cxx.find_library('pam', required: true)
libcrypto = dependency('libcrypto', required : true)
libssl = dependency('libssl', required : true)

if get_option('tests').enabled()
  #Link with subproject and generate cli utility to gen acf
  sp = subproject('ce-login', default_options : 'bin=true')
  libcelogin_dep = sp.get_variable('lib_ce_login_dep')
  pam_ibmacf_ut_deps = [libcrypto, libssl, libcelogin_dep, pam]

  #get a handle on public key directory for testing
  pubkeydir = sp.get_variable('pubkey')
  #build header file for pam module
  #to specify file locations for service file and prod/dev key
  buildroot = meson.project_build_root()
  pamtestservice_data = configuration_data()
  pamtestservice_data.set('moduledir', buildroot + '/pam_ibmacf_unit_test_lib.so')
  configure_file(input : 'conf/pamtestservice.in',
                 output : 'pamtestservice',
                 configuration : pamtestservice_data )
  testconf_data = configuration_data()
  testconf_data.set('servicefiledir', buildroot + '/service.acf')
  testconf_data.set('ibmacf_prod_key', buildroot + '/' + '@0@'.format(pubkeydir))
  testconf_data.set('ibmacf_dev_key', buildroot + '/' + '@0@'.format(pubkeydir))
  configure_file(input : 'tests/testconf.h.in',
                 output : 'testconf.h',
                 configuration : testconf_data)

  #Name pam_ibmacf test library differently as we're modifying behavior
  #We redefine the location of the service files and public keys
  #so we can test this feature atomically.
  #sdbus functionality is also pulled out when building this test lib
  #focus on testing should be on the pam module calls and calls to ce-login
  #for acf validation
  pam_ibmacf_dep = library('pam_ibmacf_unit_test_lib', 'src/pam_ibmacf.cpp', pic : true, name_prefix : '', dependencies : pam_ibmacf_ut_deps, cpp_args : '-DRUN_UNIT_TESTS', install : false)

  #Dependencies required for testing pam modules
  lib_pam_wrapper = dependency('pam_wrapper', required : true, fallback : ['pam_wrapper', 'lib_pam_wrapper_dep'])
  sp = subproject('pam_wrapper')
  pam_wrapper_lib = sp.get_variable('pam_wrapper_lib')
  pamtest_lib = sp.get_variable('pamtest_lib')
  pam_wrapper_inc= sp.get_variable('inc_dir')
  testpamwraplib = library('pam_wrap_tests', 'tests/pam_wrap_tests.c', name_prefix : '', dependencies : pam, link_with :  [pam_wrapper_lib, pamtest_lib], include_directories : pam_wrapper_inc)

  gtest = dependency('gtest', main: true,disabler: true, required : true)
  gtest_ut_deps = [gtest, libcrypto, libssl, libcelogin_dep, pam, lib_pam_wrapper]

  #Environment variables needed when running meson test
  #PAM_WRAPPER is needed to enable pam_wrapper lib ans
  #PAM_WRAPPER_SERVICE_DIR specifies custom directory for
  #pam service configuration files normally found in /etc/pam.d
  env_pam_wrapper_test = ['PAM_WRAPPER=1',
                          'PAM_WRAPPER_SERVICE_DIR=' + buildroot + '/pamtestservice',
                          'LD_PRELOAD=' + buildroot + '/subprojects/pam_wrapper/libpam_wrapper.so'
                         ]

  test('ibm-acf module', executable('gtest_pam_ibm_acf', 'tests/gtest_pam_module_unit_test.cc', dependencies : gtest_ut_deps, link_with : [pam_ibmacf_dep, testpamwraplib, pam_wrapper_lib, pamtest_lib]), env : env_pam_wrapper_test )

else
  sdbusplus = dependency('sdbusplus', version : '>=1.0.0', required : true, fallback : ['sdbusplus', 'sdbusplus_dep' ])
  #library we normally build/install in openbmc context
  sp = subproject('ce-login')
  libcelogin_dep = sp.get_variable('lib_ce_login_dep')
  deps = [sdbusplus, libcrypto, libssl, libcelogin_dep, pam]

  # sub directores may add source files and include directoies
  sources = []
  incdir = []
  subdir('src')

  library('pam_ibmacf', sources, include_directories : incdir, pic : true, name_prefix : '', dependencies : deps, install : true, install_dir : '/lib/security')
endif
