#!/usr/bin/env python3

"""
Simple test and benchmark of Python extension for Xenoncat's Equihash solver.
"""

import sys
import argparse
import os.path
import time


# Test input.
beta1_block2 = bytes([
    0x04, 0x00, 0x00, 0x00, 0x91, 0x5f, 0xa6, 0x1c,
    0x4f, 0xa5, 0x92, 0x3c, 0xe6, 0xee, 0xad, 0x06,
    0x74, 0x6b, 0x61, 0x22, 0x54, 0x94, 0xea, 0x5a,
    0x2a, 0x97, 0xae, 0x46, 0x6e, 0x6f, 0xaa, 0x9c,
    0x6e, 0xf6, 0x3a, 0x0d, 0xa5, 0xfc, 0x67, 0xd7,
    0xf8, 0xdc, 0x78, 0xc3, 0xc8, 0x70, 0xca, 0x09,
    0xba, 0xab, 0xaa, 0xf7, 0x02, 0x59, 0x68, 0xa8,
    0x6f, 0xeb, 0x88, 0x75, 0xd3, 0xf3, 0xff, 0xa7,
    0x2e, 0xb0, 0x0f, 0x81, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x66, 0xce, 0xd2, 0x57,
    0x0f, 0x0f, 0x0f, 0x20, 0x00, 0x00, 0xf7, 0xf1,
    0x94, 0xa2, 0x53, 0x8e, 0x42, 0x5f, 0x21, 0x33,
    0xcf, 0xa8, 0xd3, 0xcb, 0xf4, 0xdf, 0x71, 0xef,
    0x38, 0x28, 0x51, 0x75, 0xcf, 0xed, 0xcb, 0x3e ])


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

    parser = argparse.ArgumentParser(
        description="Test and benchmark of Python extension for "+
                    "Xenoncat's Equihash solver")
    parser.add_argument('--input', action='store', type=str,
        help='Input file containing 136-byte block header')
    parser.add_argument('--niter', action='store', type=int, default=10,
        help='Number of iterations to test')
    parser.add_argument('--nonce', action='store', type=int, default=58,
        help='Nonce value to use for first iteration')
    parser.add_argument('--avx', action='store', type=int, choices=(1, 2),
        help='Select AVX instruction set (1 for AVX1, 2 for AVX2)')
    parser.add_argument('--hugetlb', action='store_true',
        help='Allocate working memory in huge pages')
    parser.add_argument('--no-hugetlb', action='store_false', dest='hugetlb',
        help='Do not allocate working memory in huge pages')

    args = parser.parse_args()

    inputheader = beta1_block2

    if args.input is not None:
        print("using '%s' to prepare midstate" % args.input)

        with open(args.input, 'rb') as f:
            inputheader = f.read()

        if len(inputheader) not in (136, 140):
            print("ERROR: need 136 bytes in '%s'" % args.input,
                  file=sys.stderr)
            sys.exit(1)

    else:
        print("using beta1 testnet block2 to prepare midstate")

    print("Initialize Equihash engine ...")
    avxversion = -1 if args.avx is None else args.avx
    hugetlb    = -1 if args.hugetlb is None else (1 if args.hugetlb else 0)

    eqh = equihash_xenoncat.EquihashXenoncat(avxversion=avxversion,
                                             hugetlb=hugetlb)

    print("  avxversion=%d, hugetlb=%r" % (eqh.avxversion, eqh.hugetlb))

    print("Prepare midstate ...")
    eqh.prepare(inputheader[:136])

    print("Warm up ...")
    nonce = 0
    (runtime, solutions) = timeit(eqh.solve, nonce)
    print("  time = %.6f seconds, solutions = %d" %
          (runtime, len(solutions)))

    print("Running %d iterations ... " % args.niter)

    niter = args.niter
    total_time = 0
    nsolution = 0

    for i in range(niter):

        nonce = args.nonce + i
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

