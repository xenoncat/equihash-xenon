#!/usr/bin/env python3

from distutils.core import setup, Extension
from distutils.spawn import spawn
import distutils.command.build
import distutils.command.clean

class MyBuild(distutils.command.build.build):
    def run(self):
        spawn([ 'make' ])
        super().run()

class MyClean(distutils.command.clean.clean):
    def run(self):
        super().run()
        spawn([ 'make', 'clean' ])

setup(name='equihash_xenoncat',
      version='0.1',
      description='Python wrapper for Xenoncat Equihash solver',
      ext_modules=[
        Extension(name='equihash_xenoncat',
                  sources=['equihash_xenoncat.c'],
                  extra_compile_args=['-std=gnu11'],
                  extra_objects=['equihash_lib_avx1.o',
                                 'equihash_lib_avx2.o']) ],
      cmdclass={'build': MyBuild, 'clean': MyClean} )

