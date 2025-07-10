NERCfilt - version 1.0

NERCfilt - A password enforcement moduel like Microsoft's passfilt in years
past, but NERC compliant for strong password criteria!


This source code and binary library set are designed to assist you in 
making a password filter DLL for all recent incarnations of Windows.

It will work out of the box to:
- Ensure a password length of 10 or more characters.
- That at least one upper case letter is present in the password.
- That at least one lower case letter is present in the password.
- That at least one number is present in the password.
- That at least one punctuation character is present in the password.

This allows one to be compliant with the NERC CIP-005-3 and 
CIP-007-3 regulations.

It has been tested to verify that it passes only qualified passwords 
through the filter.

INSTALATION:

You will need to install this on all domain controllers in a domain 
if you want it to affect the whole domain.  It will work just as well 
on an individual machine.

Binaries are located in the binaries\x86 or binaries\x64 directory.  
If you are having trouble with this binary, you can try the debug 
version.

I strongly recommend using the release versions for production systems.

In order to install the filter, you must, in an ELEVATED cmd.exe shell:
- Copy the 32 or 64 bit binary to your \Windows\System32 directory.
- Call "regsvr32 NERCfilt.dll" from the \Windows\System32 directory.


UNINSTALL:

In order to uninstall the filter, you must, in an ELEVATED cmd.exe shell:
- Call "regsvr32 /u NERCfilt.dll" from the \Windows\System32 directory.


BUILDING:

In order to build this, you must use Visual Studio 2010 or later.

Double click on the solution and build for your target environment with the latest Windows SDK.


OTHER:

This was written as a favor to my friend Neil, and is placed into the public domain for all time under the GNU Lesser General Public License, included with this file.  

SHAMELESS PLUG:

Peak Security is a security company capable of assisting you in any security
related needs you might have.  If you are interested in services involving
security audit, penetration testing, custom security applications, or problems
that you can't find anyone else to help you deal with.  Please get in touch!
Our web site is: http://www.peaksec.com

	Thanks,
	-Mark Carey, VP R&D Peak Security, Inc.  (mark@peaksec.com).

I'm a trouble-shooter, nobody knows the troubles I've shot...
