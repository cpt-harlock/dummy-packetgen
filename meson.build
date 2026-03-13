project('packetgenlatency', 'c',
    version: '1.0',
    default_options: ['warning_level=3'])

dpdk_dep = dependency('libdpdk', required: true)

executable('packetgenlatency',
    sources: ['main.c'],
    dependencies: [dpdk_dep])
