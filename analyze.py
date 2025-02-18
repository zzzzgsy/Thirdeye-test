import sys
from Analysis.Analysis import *

if (len(sys.argv)) < 2:
    print("Usage: python analyze.py package_name")
    exit(0)
pkg_name = sys.argv[1]

print('Analyzing Crypt Mitm...')
analyse_crypt_mitm(pkg_name)

print('Analyzing Crypt Pcap...')
analyse_crypt_pcap(pkg_name)

print('Analyzing Printable Pcap...')
extract_pcap_printable(pkg_name)

# print('Analyzing Printable File IO...')
# extract_fileio_printable(pkg_name)

# print('Analyzing Crypt File IO...')
# analyse_crypt_fileio(pkg_name)