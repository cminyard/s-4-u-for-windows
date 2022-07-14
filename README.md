# s(4)u for Windows - Hacked up by me #

s4u is a demonstration program using the [Service For User Logon (S4U)
Extension](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
of the [MSV1_0 Authentication
Package](https://docs.microsoft.com/en-us/windows/win32/secauthn/msv1-0-authentication-package).

It allows the creation of a `cmd.exe` with the context of any user
without requiring the password.

WARNING: This is a test program.  It does not practice good password
hygiene.  This is only for demonstration and testing.

## Caveats ##

Users do not

## Privileges ##

The invoking user must have the following privileges (aka User Rights; aka Account Rights):

* `SeTcbPrivilege`: Act as part of the operating system.
* `SeIncreaseQuotaPrivilege`: Adjust memory quotas for a process.
* `SeAssignPrimaryTokenPrivilege`: Replace a process-level token.

You can use the [Carbon Grant-Privilege PowerShell cmdlet](https://get-carbon.org/Grant-Privilege.html)
to grant the privileges.

To grant the privileges to the current user and create a test `user` execute:

```powershell
choco install -y carbon
Import-Module Carbon
Grant-Privilege $env:USERNAME 'SeTcbPrivilege'
Grant-Privilege $env:USERNAME 'SeIncreaseQuotaPrivilege'
Grant-Privilege $env:USERNAME 'SeAssignPrimaryTokenPrivilege'
New-LocalUser `
    -Name user `
    -Password (ConvertTo-SecureString 'HeyH0Password' -AsPlainText -Force) `
    -PasswordNeverExpires `
    | Out-Null
Grant-Privilege user 'SeBatchLogonRight'
Restart-Computer
```

## Usage ##

Use the program as following:

    s4u.exe [options] [<domain>\]user

Options are:
* --lsa - Use LsaLogonUser to log the user on.  This is required for
  an S4U logon.  Note that --s4u is ignore without this.
* --s4u - Do an S4u logon without a password.  The --pw is ignored if this
  is specified.
* --pw <password> - Pass in the password to use for logging in.  Required
  if --s4u is not specified.
* --lsid - Pull the logon sid from the calling program, or from an active
  session if the calling program doesn't have one.  Your logon will not
  work very well without this, important DLLs will crash without a
  logon sid.  Does not work with --lsa.
* --esids - Add interactive SIDs to the logon.
* --priv - Do not drop administrator privileges, only works with --s4u.
* --puser - Just print out the calling users auth token and quit.

As you can tell, these are all kind of a hack.  If you don't give any
options, it won't work.  If you give a password and no option:

   s4u.exe -pw <password> user

it will sort of work, but the program will not have a logon SID.  And
--lsid doesn't work without --lsa.

The best chance of working is with:

    s4u.exe --lsid --lsa --pw <password> user

Which will give you a normal logon like you had started a shell.  If
you so S4U:

    s4u.exe --lsid --lsa --s4u user

you will get a logon that is very close to a normal login.  However,
it has (at least) three issues:

* There is no linked SID for an administrator account.  So if you are
  running as an administrator, you cannot do any administrative actions.
* The TokenElevation value is wrong.  I do not know the consequences of
  that.
* There are no credentials stored with the login, so anything that could
  use stored credentials, like mounting shares, will require you to
  enter a password.

I do know know if it is possible to fix these issues.  The only option
I know of that might solve all but the last one is to create a custom
LSA authentication package.

Any help on this from others would be greatly appreciated.

## Other Info ##

This code has, commented out, an example of how to use
NtCreateToken().

## References ##

* [Logon as a user without a password](https://docs.microsoft.com/en-us/archive/blogs/winsdk/logon-as-a-user-without-a-password)
* [[MS-SFU]: Kerberos Protocol Extensions: Service for User and Constrained Delegation Protocol](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/3bff5864-8135-400e-bdd9-33b552051d94)
* [Switching the user context without password, Method 1: Kerberos/MsV1_0 S4U authentication](https://cygwin.com/cygwin-ug-net/ntsec.html#ntsec-nopasswd1)
