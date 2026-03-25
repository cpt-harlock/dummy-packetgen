project('packetgenlatency', 'c',
    version: '1.0',
    default_options: ['warning_level=3'])

dpdk_dep = dependency('libdpdk', required: true)

cc = meson.get_compiler('c')

# Find the math library ('m')
# 'required: false' is a good practice for the math library
# as some platforms (like modern glibc or Windows) might merge it into the standard C library
m_dep = cc.find_library('m', required : false)

executable('packetgenlatency',
    sources: ['main.c'],
    dependencies: [dpdk_dep,m_dep])
