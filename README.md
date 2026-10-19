Hexpress

High efficiency vector lattice compression suite. Features recursive dictionary mapping for bit-perfect reconstruction of large scale genomic and binary datasets.

Technical Overview: The Hexpress Suite
This repository provides two primary utilities for managing high accuracy data forensics and storage: hex-press.cpp (Packer) and hex-tract.cpp (Unpacker).

1. hex-press (The Packer)
The packer treats data as a traversal through a sliding 4-byte window, building a dynamic vector lattice (dictionary) on the fly.

 * Lattice Mapping: Scans for 32-bit chunks and assigns them a 12-bit ID once they are identified as recurring patterns.
   
 * Bit-Level Efficiency: Uses a BitWriter to pack 1-bit flags (match vs. literal) and variable-width data into a compact binary .vxl format.
   
 * Integrity Anchor: Automatically calculates and embeds a SHA-256 hash of the source file into the header to ensure sovereign data verification.
   
2. hex-tract (The Unpacker)
The unpacker performs bit-perfect reconstruction by mirroring the lattice-building logic of the packer.

 * Mirror Logic: Rebuilds the exact same 4,096-entry lattice used during compression, ensuring no data is lost or altered.
   
 * Auto-Verification: Upon completion, it performs a secondary SHA-256 check on the reconstructed file and compares it against the embedded "Expected Hash".
   
 * Verdict Reporting: Provides an immediate [PASS] or [FAIL] status based on bitwise identity.
   
Quick Start (ARMv9 / Linux)
To compile these tools with optimizatio for your architecture:

# Compile the Packer
clang++ -O3 -march=armv9-a hex-press.cpp -o hex-press

# Compile the Unpacker
clang++ -O3 -march=armv9-a hex-tract.cpp -o hex-tract

# Compress a file
./hex-press ecoli.fasta

# Reconstruct a file
./hex-tract ecoli.fasta.vxl

License
Distributed under the GNU General Public License v3.0 (GPL-3.0).

Research documentation anchored by Unified Fractal Theory. https://doi.org/10.5281/zenodo.18152385

Support the Research

Buy Me A Coffee: buymeacoffee.com/tourneyx

PayPal: @XaiTourney
