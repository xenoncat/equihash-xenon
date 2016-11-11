"""
Validate Equihash solutions.
"""

import copy
import struct
import blake2b


def expandSolution(n, k, solution):
    """Expand compact solution into list of indices."""

    solutionlen  = 2**k
    solutionbits = n // (k + 1) + 1

    assert 8 * len(solution) == solutionlen * solutionbits

    indices = solutionlen * [ 0 ]
    word = 0
    bits = 0
    p = 0

    for i in range(solutionlen):
        while bits < solutionbits:
            word = (word << 8) | solution[p]
            p += 1
            bits += 8
        bits -= solutionbits
        indices[i] = (word >> bits)
        word = word & ((1 << bits) - 1)

    return indices


def compressSolution(n, k, indices):
    """Compress list of indices into compact solution."""

    solutionlen  = 2**k
    solutionbits = n // (k + 1) + 1
    assert (solutionlen * solutionbits) % 8 == 0
    assert solutionlen == len(indices)

    solution = bytearray(solutionlen * solutionbits // 8)

    word = 0
    bits = 0
    p = 0

    for i in indices:
        word = (word << solutionbits) | i
        bits += solutionbits
        while bits >= 8:
            bits -= 8
            solution[p] = (word >> bits)
            p += 1
            word = word & ((1 << bits) - 1)

    assert p == len(solution)
    return solution


def generateWord(n, ctx, idx):
    """Generate n-bit word at specified index."""

    bytesPerWord = n // 8
    wordsPerHash = 512 // n
       
    hidx = idx // wordsPerHash
    hrem = idx % wordsPerHash 

    idxdata = struct.pack('<I', hidx)
    ctx1 = copy.deepcopy(ctx)
    blake2b.blake2b_update(ctx1, idxdata)
    digest = blake2b.blake2b_final(ctx1)

    w = 0
    for i in range(hrem*bytesPerWord, hrem*bytesPerWord+bytesPerWord):
        w = (w << 8) | digest[i]

    return w


def validateSolution(n, k, header, solution):
    """Validate an Equihash solution.

    n           (int)   -- Word length in bits
    k           (int)   -- 2-log of number of indices per solution
    header      (bytes) -- Block header with nonce, 140 bytes
    solution    (bytes) -- Compact solution, (n/(k+1)+1)*2**(k-3) bytes

    Return True if solution is valid, False if not.
    """

    assert n > 1
    assert k >= 3
    assert n % 8 == 0
    assert n % (k + 1) == 0

    solutionlen = 2**k
    indices = expandSolution(n, k, solution)
    assert len(indices) == solutionlen

    # Check for duplicate indices.
    if len(set(indices)) != len(indices):
        return False

    # Generate hash words.
    bytesPerWord = n // 8
    wordsPerHash = 512 // n
    outlen = wordsPerHash * bytesPerWord

    personal = b'ZcashPoW' + struct.pack('<II', n, k)
    ctx = blake2b.Blake2bState(outlen=outlen, key=b'', personal=personal)
    blake2b.blake2b_update(ctx, header)

    words = solutionlen * [ 0 ]
    for i in range(solutionlen):
        words[i] = generateWord(n, ctx, indices[i])

    # Check pair-wise ordening of indices.
    for s in range(k):
        d = 1 << s
        for i in range(0, solutionlen, 2*d):
            if indices[i] >= indices[i+d]:
                return False

    # Check XOR conditions.
    bitsPerStage = n // (k + 1)
    for s in range(k):
        d = 1 << s
        for i in range(0, solutionlen, 2*d):
            w = words[i] ^ words[i+d]
            if (w >> (n - (s + 1) * bitsPerStage)) != 0:
                return False
            words[i] = w

    # Check final sum zero.
    return words[0] == 0


def main():
    """Run a few test vectors."""

    testvectors = [
        (96, 5, b"block header", 1,
         [ 1911, 96020, 94086, 96830, 7895, 51522, 56142, 62444, 15441, 100732, 48983, 64776, 27781, 85932, 101138, 114362, 4497, 14199, 36249, 41817, 23995, 93888, 35798, 96337, 5530, 82377, 66438, 85247, 39332, 78978, 83015, 123505 ]),
        (96, 5, b"Equihash is an asymmetric PoW based on the Generalised Birthday problem.", 2,
         [ 6005, 59843, 55560, 70361, 39140, 77856, 44238, 57702, 32125, 121969, 108032, 116542, 37925, 75404, 48671, 111682, 6937, 93582, 53272, 77545, 13715, 40867, 73187, 77853, 7348, 70313, 24935, 24978, 25967, 41062, 58694, 110036 ]),
        (200, 9, b"block header", 0,
         [ 4313, 223176, 448870, 1692641, 214911, 551567, 1696002, 1768726, 500589, 938660, 724628, 1319625, 632093, 1474613, 665376, 1222606, 244013, 528281, 1741992, 1779660, 313314, 996273, 435612, 1270863, 337273, 1385279, 1031587, 1147423, 349396, 734528, 902268, 1678799, 10902, 1231236, 1454381, 1873452, 120530, 2034017, 948243, 1160178, 198008, 1704079, 1087419, 1734550, 457535, 698704, 649903, 1029510, 75564, 1860165, 1057819, 1609847, 449808, 527480, 1106201, 1252890, 207200, 390061, 1557573, 1711408, 396772, 1026145, 652307, 1712346, 10680, 1027631, 232412, 974380, 457702, 1827006, 1316524, 1400456, 91745, 2032682, 192412, 710106, 556298, 1963798, 1329079, 1504143, 102455, 974420, 639216, 1647860, 223846, 529637, 425255, 680712, 154734, 541808, 443572, 798134, 322981, 1728849, 1306504, 1696726, 57884, 913814, 607595, 1882692, 236616, 1439683, 420968, 943170, 1014827, 1446980, 1468636, 1559477, 1203395, 1760681, 1439278, 1628494, 195166, 198686, 349906, 1208465, 917335, 1361918, 937682, 1885495, 494922, 1745948, 1320024, 1826734, 847745, 894084, 1484918, 1523367, 7981, 1450024, 861459, 1250305, 226676, 329669, 339783, 1935047, 369590, 1564617, 939034, 1908111, 1147449, 1315880, 1276715, 1428599, 168956, 1442649, 766023, 1171907, 273361, 1902110, 1169410, 1786006, 413021, 1465354, 707998, 1134076, 977854, 1604295, 1369720, 1486036, 330340, 1587177, 502224, 1313997, 400402, 1667228, 889478, 946451, 470672, 2019542, 1023489, 2067426, 658974, 876859, 794443, 1667524, 440815, 1099076, 897391, 1214133, 953386, 1932936, 1100512, 1362504, 874364, 975669, 1277680, 1412800, 1227580, 1857265, 1312477, 1514298, 12478, 219890, 534265, 1351062, 65060, 651682, 627900, 1331192, 123915, 865936, 1218072, 1732445, 429968, 1097946, 947293, 1323447, 157573, 1212459, 923792, 1943189, 488881, 1697044, 915443, 2095861, 333566, 732311, 336101, 1600549, 575434, 1978648, 1071114, 1473446, 50017, 54713, 367891, 2055483, 561571, 1714951, 715652, 1347279, 584549, 1642138, 1002587, 1125289, 1364767, 1382627, 1387373, 2054399, 97237, 1677265, 707752, 1265819, 121088, 1810711, 1755448, 1858538, 444653, 1130822, 514258, 1669752, 578843, 729315, 1164894, 1691366, 15609, 1917824, 173620, 587765, 122779, 2024998, 804857, 1619761, 110829, 1514369, 410197, 493788, 637666, 1765683, 782619, 1186388, 494761, 1536166, 1582152, 1868968, 825150, 1709404, 1273757, 1657222, 817285, 1955796, 1014018, 1961262, 873632, 1689675, 985486, 1008905, 130394, 897076, 419669, 535509, 980696, 1557389, 1244581, 1738170, 197814, 1879515, 297204, 1165124, 883018, 1677146, 1545438, 2017790, 345577, 1821269, 761785, 1014134, 746829, 751041, 930466, 1627114, 507500, 588000, 1216514, 1501422, 991142, 1378804, 1797181, 1976685, 60742, 780804, 383613, 645316, 770302, 952908, 1105447, 1878268, 504292, 1961414, 693833, 1198221, 906863, 1733938, 1315563, 2049718, 230826, 2064804, 1224594, 1434135, 897097, 1961763, 993758, 1733428, 306643, 1402222, 532661, 627295, 453009, 973231, 1746809, 1857154, 263652, 1683026, 1082106, 1840879, 768542, 1056514, 888164, 1529401, 327387, 1708909, 961310, 1453127, 375204, 878797, 1311831, 1969930, 451358, 1229838, 583937, 1537472, 467427, 1305086, 812115, 1065593, 532687, 1656280, 954202, 1318066, 1164182, 1963300, 1232462, 1722064, 17572, 923473, 1715089, 2079204, 761569, 1557392, 1133336, 1183431, 175157, 1560762, 418801, 927810, 734183, 825783, 1844176, 1951050, 317246, 336419, 711727, 1630506, 634967, 1595955, 683333, 1461390, 458765, 1834140, 1114189, 1761250, 459168, 1897513, 1403594, 1478683, 29456, 1420249, 877950, 1371156, 767300, 1848863, 1607180, 1819984, 96859, 1601334, 171532, 2068307, 980009, 2083421, 1329455, 2030243, 69434, 1965626, 804515, 1339113, 396271, 1252075, 619032, 2080090, 84140, 658024, 507836, 772757, 154310, 1580686, 706815, 1024831, 66704, 614858, 256342, 957013, 1488503, 1615769, 1515550, 1888497, 245610, 1333432, 302279, 776959, 263110, 1523487, 623933, 2013452, 68977, 122033, 680726, 1849411, 426308, 1292824, 460128, 1613657, 234271, 971899, 1320730, 1559313, 1312540, 1837403, 1690310, 2040071, 149918, 380012, 785058, 1675320, 267071, 1095925, 1149690, 1318422, 361557, 1376579, 1587551, 1715060, 1224593, 1581980, 1354420, 1850496, 151947, 748306, 1987121, 2070676, 273794, 981619, 683206, 1485056, 766481, 2047708, 930443, 2040726, 1136227, 1945705, 1722044, 1971986 ]),
    ]

    nfail = 0

    for (n, k, hdr, nonce, soln) in testvectors:
        print("Testing n=%d k=%d hdr=%r nonce=%d ..." % (n, k, hdr, nonce))
        hdrdata = hdr + struct.pack('<I', nonce) + 28 * b'\x00'
        soldata = compressSolution(n, k, soln)
        v = validateSolution(n, k, hdrdata, soldata)
        if not v:
            print("FAILED")
            nfail += 1
        else:
            print("ok")

    print(nfail, "failed tests")
    assert nfail == 0


if __name__ == '__main__':
    main()

