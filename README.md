# Post Quantum Secure Oblivious Transfer Extension
We implemented a 1-out-of-2 post quantum secure Oblivious Transfer (OT) extension protocol that
builds on the base OT proposed by Niklas Büscher, Daniel Demmler, Nikolaos P. Karvelas, Stefan Katzenbeisser, Juliane Krämer, Deevashwer Rathee, Thomas Schneider, and Patrick Struck in the paper ["Secure Two-Party Computation in a Quantum World"](https://eprint.iacr.org/2020/411). We
adapted the protocol advances of the paper ["More Efficient Oblivious Transfer Extensions"](https://eprint.iacr.org/2016/602) by Gilad Asharov, Yehuda Lindell, Thomas Schneider, and Michael Zohner, in order to efficiently implement large OTs in a quantum secure environment.
The extension protocol uses the learning with errors (LWE) problem, in particular the ring LWE variant, to provide security against quantum adversaries. We implemented the protocol based on the [PQ-MPC implementation](https://github.com/encryptogroup/PQ-MPC) of Encryptogroup. Benchmarking results indicate successful performance in handling up to 2<sup>19</sup> OTs, with time and communication overhead comparable to the basic OT phase. With the remote virtualization server, we can extend the maximal executable OT number from 2<sup>20</sup> to 2<sup>23</sup>.

## Environment:
 - Our implementation builds on Linux OS.
 - C++ packages(g++, cmake, make)
 - libgmp-dev 
 - SEAL (version 3.1.0) ( which is part as git module and don't need to be downloaded)
 - libssl-dev
## SEAL installation:
 - SEAL (version 3.1.0) is pre-downloaded and unzipped under ```./extern/SEAL-3.1.0```. please check this folder which contains the official README file and finish the installation(we suggest the global installation) as follows.
```
cd extern/SEAL-3.1.0/src
cmake .
make
sudo make install
cd ..
```
 - The error during installation is solved by adding ```#include <mutex>``` in ```./src/seal/util/locks.h```.

## Compilation

To compile the code under ```code``` folder:
```
mkdir build && cd build
cmake .. && make
```

## Tests

After compilation, the .exe file named pqot is in `build/bin/`.Go to this location, then run the test binaries as follows to make sure everything works as intended:

```
./pqot <role> <port>
```
In the argument "role", 1 represents Alice and 2 represents Bob. Moreover, both need to use the same port:
```
./pqot 1 8000 & ./pqot 2 8000 

```
## Acknowledgements
The following directories contain code from external repositories:  

`emp-tool`: inheritet from the base OT repository, this provides cryptographic building blocks used in base OT and channel support for our implementation.  
`extern`: this contains pre-downloaded SEAL library.  
`pq-ot`: this contains pre-implemented base OT.
