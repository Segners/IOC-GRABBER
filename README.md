# IOC_Grabber

Original by https://github.com/Oni-kuki

### Prerequisite  
  
On linux machine for ``Hash-Parser`` and ``Munin`` part ``git`` is necessary.  
*Debian*
```
apt install git
```
*Arch-linux*
```
pacman -S git
```
## Installation
* *Linux*  
```
git clone https://github.com/Segners/IOC-GRABBER
```  
* *Windows*  
However for the file ``IOC_Grabber.ps1`` it's possible that you are obliged to work in Offline in an optics of Forensic so you can obviously use other way to make it available on your machine.  
Otherwise you can also install ``git`` on Windows.  
you can easily do this with the ``chocolatey`` package manager  
https://chocolatey.org/  
~~You can also use the compiled file provided~~  
## **IOC_Grabber**

Just a small module to get all interesting IOC's on Windows
and analyze the hashes of different file types like .exe, .sys, .dll to compare them with different API's from :
Virustotal, HybridAnalysis, Any.Run, URLhaus, MISP, CAPE, Malshare, Valhalla, Hashlookup.  
(For some tools it's just a matter of checking the URL, of course).  
```
./IOC_Grabber.ps1
```
