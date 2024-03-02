#
# to build with Meson build system (https://mesonbuild.com/index.html),
#
# ```
# meson build
# cd build
# ninja
# ```
#
# You can get meson from here (https://mesonbuild.com/Getting-meson.html).
#

project('certify',
  'cpp',
  version: '0.0.0',
  default_options: [
    'cpp_std=c++11',
  ],
  license: 'BSL-1.0',
)


certify_dep = declare_dependency(
  include_directories: include_directories('include'),
)

# build examples
if not meson.is_subproject()

  extra_deps = declare_dependency(
    dependencies: [
      dependency('boost'),
      dependency('openssl'),
      dependency('threads'),
    ]
  )

  if host_machine.system() == 'windows'
    os_unique_deps = declare_dependency(
      link_args: ['Crypt32.lib']
    )
  elif host_machine.system() == 'darwin'
    os_unique_deps = declare_dependency(
      link_args: [
        '-framework CoreFoundation',
        '-framework Security',
        '-Wl',
        '-F/Library/Frameworks',
      ]
    )
  else
    error('unknown OS detected.')
  endif

  subdir('examples')
endif