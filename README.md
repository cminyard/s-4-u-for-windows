# s(4)u for Windows #

[![Build status](https://github.com/aurel26/s-4-u-for-windows/workflows/Build/badge.svg)](https://github.com/aurel26/s-4-u-for-windows/actions?query=workflow%3ABuild)

s4u is a demonstration program using the [Service For User Logon (S4U) Extension](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94) of the [MSV1_0 Authentication Package](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package).

It allows the creation of a `cmd.exe` with the context of any user without requiring the password.

## Usage ##

Create a cmd.exe with a local user security context:

    s4u.exe .\user

Create a cmd.exe with a domain user security context:

    s4u.exe DOMAIN\user

Create a cmd.exe with and add specific SID:

    s4u.exe .\user S-1-5-18

## References ##

* [Logon as a user without a password](https://docs.microsoft.com/en-us/archive/blogs/winsdk/logon-as-a-user-without-a-password)
* [[MS-SFU]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
* [Switching the user context without password, Method 1: Kerberos/MsV1_0 S4U authentication](https://cygwin.com/cygwin-ug-net/ntsec.html#ntsec-nopasswd1)
