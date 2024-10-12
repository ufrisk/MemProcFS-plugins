Plugins for MemProcFS
===============================
This repository contains various non-core plugins for [MemProcFS - The Memory Process File System](https://github.com/ufrisk/MemProcFS).

Plugins range from non-core plugins to plugins that have offensive capabilities - such as _pypykatz_. Please find a short description for each plugin below:

## pypykatz regsecrets

#### Author:
Tamas Jos ([@skelsec](https://twitter.com/SkelSec)) , info@skelsec.com , https://github.com/skelsec/

#### Overview:
_regsecrets_ for MemProcFS exposes mimikatz functionality in the folder `/py/regsecrets/` in the file system root provided that the target is a supported Windows system. Functionality includes retrieval NTLM hashes for local accounts amongst other things.
<p align="center"><img src="https://raw.githubusercontent.com/wiki/ufrisk/MemProcFS-plugins/resources/p_regsecrets_1.png" height="375"/></p>

#### Installation instructions:
1) Ensure MemProcFS supported version of 64-bit Python for Windows is on the system path (or specify in `-pythonpath` option when starting MemProcFS). NB! embedded Python will not work with _pypykatz_ and _aiowinreg_ since it requires access to Python pip installed packages.
2) Install _pypykatz_ and _aiowinreg_ pip package, in correct python environment, by running `pip install pypykatz aiowinreg`.
3) Copy the _pyregsecrets_ for _MemProcFS_ plugin by copying all files from [`/files/plugins/pym_regsecrets`](https://github.com/ufrisk/MemProcFS-plugins/tree/master/files/plugins/pym_regsecrets) to corresponding folder in MemProcFS - overwriting any existing files there.
4) Start MemProcFS.

#### Last updated: 2021-03-21
