#!/usr/bin/env python3

"""
Simple test and benchmark of Python extension for Xenoncat's Equihash solver.
"""

import sys
import argparse
import os.path
import time

# Import the extension module.
try:
    import equihash_xenoncat

except ImportError:
    # Importing failed. Perhaps the extension was built but not yet installed.
    import distutils.util
    sys.path.append(os.path.join('build', 'lib.' +
                                 distutils.util.get_platform() + '-' +
                                 sys.version[:3]))
    import equihash_xenoncat


def timeit(func, *args):
    """Run func(args) and return (runtime, func_return)."""

    t1 = time.monotonic()
    ret = func(*args)
    t2 = time.monotonic()
    return (t2 - t1, ret)


def main():

# TODO : parse command line arguments

    niter = 10
    startnonce = 58

    inputheader = b''

    try:
        with open('../Linux/demo/input.bin', 'rb') as f:
            inputheader = f.read()
        print("using input.in to prepare midstate")
    except FileNotFoundError:
        print("input.bin not found, using sample data (beta1 testnet block2)",
              file=sys.stderr)

    if len(inputheader) != 140:
        print("ERROR: need exactly 140 bytes in input.bin",
              file=sys.stderr)
        sys.exit(1)

# TODO : avxversion, hugetlb
    print("Initialize Equihash engine ...")
    eqh = equihash_xenoncat.EquihashXenoncat()

    print("Prepare midstate ...")
    eqh.prepare(inputheader[:136])

    print("Warm up ...")
    nonce = 0
    (runtime, solutions) = timeit(eqh.solve, nonce)
    print("  time = %.6f seconds, solutions = %d" %
          (runtime, len(solutions)))

    print("Running %d iterations ... " % niter)

    total_time = 0
    nsolution = 0

    for i in range(niter):

        nonce = startnonce + i
        (runtime, solutions) = timeit(eqh.solve, nonce)
        print("  time = %.6f seconds, solutions = %d" %
              (runtime, len(solutions)))

        total_time += runtime
        nsolution += len(solutions)

    print("Total time: %.6f seconds, %.6f seconds per run average" %
          (total_time, total_time / float(niter)))

    print("Total solutions: %d, %.3f Sol/s average" %
          (nsolution, nsolution / total_time))


if __name__ == '__main__':
    main()

