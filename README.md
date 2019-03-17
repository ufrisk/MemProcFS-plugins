Plugins for MemProcFS
===============================
This repository contains various non-core plugins for [MemProcFS - The Memory Process File System](https://github.com/ufrisk/MemProcFS).

Plugins range from non-core plugins to plugins that have offensive capabilities - such as _pypykatz_. Please find a short description for each plugin below:

## pypykatz

#### Author:
Tamas Jos ([@skelsec](https://twitter.com/SkelSec)) , info@skelsec.com , https://github.com/skelsec/

#### Overview:
_pypykatz_ for MemProcFS exposes mimikatz functionality in the folder `/py/secrets/` in the file system root provided that the target is a supported Windows system. Functionality includes retrieval of hashes, passwords, kerberos tickets and various other credentials.

#### Installation instructions:
1) Ensure MemProcFS supported version of 64-bit Python for Windows is on the system path (or specify in `-pythonpath` option when starting MemProcFS). NB! embedded Python will not work with _pypykatz_ since it requires access to Python pip installed packages.
2) Install _pypykatz_ pip package, in correct python environment, by running `pip install pypykatz`.
3) Copy the _pypykatz_ for _MemProcFS_ plugin by copying all files from [`/files/plugins/pym_pypykatz`](https://github.com/ufrisk/MemProcFS-plugins/tree/master/files/plugins/pym_pypykatz) to corresponding folder in MemProcFS - overwriting any existing files there.
4) Start MemProcFS.

#### Functionality:
<p align="center"><img src="https://raw.githubusercontent.com/wiki/ufrisk/MemProcFS-plugins/resources/p_pypykatz_1.png" height="175"/></p>

#### Last updated: 2019-03-17
