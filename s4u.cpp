#include <Windows.h>
#include <Ntsecapi.h>
#include <UserEnv.h>
#include <sddl.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "userenv.lib")

#define STATUS_SUCCESS           0
#define EXTRA_SID_COUNT          2

typedef struct _MSV1_0_SET_OPTION {
   MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
   DWORD dwFlag;
   BOOL bUnset;
} MSV1_0_SET_OPTION, *PMSV1_0_SET_OPTION;

HANDLE g_hHeap;

static void
print_err(const char *str, DWORD err)
{
      wchar_t errbuf[128];

      FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		    err, 0, errbuf, sizeof(errbuf), NULL);
      fprintf(stderr, "error: %s (%d): %ls\n", str, err, errbuf);
}

static void
pr_sid(int indent, const char *str, SID *sid)
{
    char *sidstr;

    if (!sid) {
	printf("%*s%s: NULL Sid\n", indent, "", str);
    } else if (ConvertSidToStringSidA(sid, &sidstr)) {
	printf("%*s%s: %s\n", indent, "", str, sidstr);
	LocalFree(sidstr);
    } else {
	printf("%*s%s: Bad Sid\n", indent, "", str);
    }
}

static void
print_sid(const char *str, SID *sid)
{
    pr_sid(0, str, sid);
}

static void
pr_sid_attr(int indent, const char *str, SID_AND_ATTRIBUTES *v)
{
    char *sidstr;

    printf("%*s%s:\n", indent, "", str);
    pr_sid(indent + 2, "Sid", (SID *) v->Sid);
    printf("%*sAttributes: 0x%x\n", indent + 2, "", v->Attributes);
}

static void
pr_sid_attr_hash(int indent, const char *str, SID_AND_ATTRIBUTES_HASH *v)
{
    unsigned int i;

    printf("%*s%s:\n", indent, "", str);
    printf("%*sSidCount: %d\n", indent + 2, "", v->SidCount);
    for (i = 0; i < v->SidCount; i++) {
	printf("%*sSidAttr[%d]:", indent + 2, "", i);
	pr_sid_attr(indent + 4, "", &v->SidAttr[i]);
    }
    for (i = 0; i < SID_HASH_SIZE; i++) {
	printf("%*sHash[%d]: 0x%lx\n", indent + 2, "", i, v->Hash[i]);
    }
}

void
pr_luid(int indent, const char *str, LUID *v)
{
    printf("%*s%s: %d:%ld\n", indent, "", str, v->LowPart, v->HighPart);
}

void
pr_luid_and_attr(int indent, const char *str, LUID_AND_ATTRIBUTES *v)
{
    pr_luid(indent, "Luid", &v->Luid);
    printf("%*sAttributes: 0x%x\n", indent, "", v->Attributes);
}

void
pr_token_priv(int indent, const char *str, TOKEN_PRIVILEGES *v)
{
    unsigned int i;

    printf("%*s%s:\n", indent, "", str);
    printf("%*sPrivilegeCount: %d\n", indent + 2, "", v->PrivilegeCount);
    for (i = 0; i < v->PrivilegeCount; i++) {
	printf("%*sPrivileges[%d]:\n", indent + 2, "", i);
	pr_luid_and_attr(indent + 4, "", &v->Privileges[i]);
    }
}

void
pr_tok_mand_pol(int indent, const char *str, TOKEN_MANDATORY_POLICY *v)
{
    printf("%*s%s.Policy: %d\n", indent, "", str, v->Policy);
}

static DWORD
read_token_info(HANDLE h, TOKEN_INFORMATION_CLASS type, void **rval,
		DWORD *rlen)
{
    DWORD err, len = 0;
    void *val;

    if (GetTokenInformation(h, type, NULL, 0, &len))
	/* This should fail. */
	return ERROR_INVALID_DATA;
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
	return err;
    val = malloc(len);
    if (!val)
	return STATUS_NO_MEMORY;
    if (!GetTokenInformation(h, type, val, len, &len)) {
	free(val);
	return GetLastError();
    }
    *rval = val;
    if (rlen)
	*rlen = len;
    return 0;
}

struct ta2 {
    PSID_AND_ATTRIBUTES_HASH SidHash;
    PSID_AND_ATTRIBUTES_HASH RestrictedSidHash;
    PTOKEN_PRIVILEGES Privileges;
    LUID AuthenticationId;
    TOKEN_TYPE TokenType;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
    TOKEN_MANDATORY_POLICY MandatoryPolicy;
    DWORD Flags;
    DWORD AppContainerNumber;
    PSID PackageSid;
    PSID_AND_ATTRIBUTES_HASH CapabilitiesHash;
    PSID TrustLevelSid;
};

static DWORD
get_dword_tokinfo(HANDLE h, TOKEN_INFORMATION_CLASS type, DWORD *val)
{
    DWORD len = sizeof(DWORD);

    if (!GetTokenInformation(h, TokenUIAccess, val, len, &len))
	return GetLastError();
    return 0;
}

static void
print_tokinfo(HANDLE inh)
{
    HANDLE h;
    DWORD err, val, len;
    struct ta2 *access_info = NULL;
    unsigned int i;

    if (inh)
	h = inh;
    else
	OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h);

    err = get_dword_tokinfo(h, TokenUIAccess, &val);
    if (err)
	print_err("Get Token UI access", err);
    else
	printf("Token UI Access: %d\n", val);

    err = get_dword_tokinfo(h, TokenSandBoxInert, &val);
    if (err)
	print_err("Get Token sandbox inert", GetLastError());
    else
	printf("Token sandbox inert: %d\n", val);

    err = get_dword_tokinfo(h, TokenIsAppContainer, &val);
    if (err)
	print_err("Get Token is App Container", GetLastError());
    else
	printf("Token is app container: %d\n", val);

    err = get_dword_tokinfo(h, TokenMandatoryPolicy, &val);
    if (err)
	print_err("Get Token mandatory policy", GetLastError());
    else
	printf("Token is mandatory policy: %d\n", val);

    err = get_dword_tokinfo(h, TokenSessionId, &val);
    if (err)
	print_err("Get Session Id", GetLastError());
    else
	printf("Token session id: %d\n", val);

    err = read_token_info(h, TokenAccessInformation, (void **) &access_info,
			  NULL);
    if (err) {
	print_err("Get access info", err);
    } else {
	printf("Access info:\n");
	pr_sid_attr_hash(2, "SidHash", access_info->SidHash);
	pr_sid_attr_hash(2, "RestrictedSidHash",
			 access_info->RestrictedSidHash);
	pr_token_priv(2, "Privileges", access_info->Privileges);
	pr_luid(2, "AuthenticationId", &access_info->AuthenticationId);
	printf("  TokenType: %d\n", access_info->TokenType);
	printf("  ImpersonationLevel: %d\n", access_info->ImpersonationLevel);
	pr_tok_mand_pol(2, "MandatoryPolicy", &access_info->MandatoryPolicy);
	printf("  Flags: %d\n", access_info->Flags);
	printf("  AppContainerNumber: %d\n", access_info->AppContainerNumber);
	pr_sid(2, "PackageSid", (SID *) access_info->PackageSid);
	pr_sid_attr_hash(2, "CapabilitiesHash", access_info->CapabilitiesHash);
	pr_sid(2, "TrustLevelSid", (SID *) access_info->TrustLevelSid);
    }

    if (!inh)
	CloseHandle(h);

    if (access_info)
	free(access_info);
}

//
// Set/Unset privilege.
//
BOOL
SetPrivilege(HANDLE hToken,
	     LPCTSTR lpszPrivilege,
	     BOOL bEnablePrivilege)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL,      // lookup privilege on local system
			      lpszPrivilege,    // privilege to lookup 
			      &luid)) {         // receives LUID of privilege
	fprintf(stderr, "LookupPrivilegeValue failed (error: %u).\n", GetLastError());
	return FALSE;
    }

   tp.PrivilegeCount = 1;
   tp.Privileges[0].Luid = luid;
   if (bEnablePrivilege)
      tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
   else
      tp.Privileges[0].Attributes = 0;

   //
   // Enable the privilege or disable all privileges.
   //
   if (!AdjustTokenPrivileges(
      hToken,
      FALSE,
      &tp,
      sizeof(TOKEN_PRIVILEGES),
      (PTOKEN_PRIVILEGES)NULL,
      (PDWORD)NULL))
   {
      fprintf(stderr, "AdjustTokenPrivileges failed (error: %u).\n", GetLastError());
      return FALSE;
   }
   else
   {
      if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
      {
         fprintf(stderr, "The token does not have the specified privilege (%S).\n", lpszPrivilege);
         return FALSE;
      }
      else
      {
         printf("AdjustTokenPrivileges (%S): OK\n", lpszPrivilege);
      }
   }

   return TRUE;
}

DWORD
get_logon_sid (HANDLE h, SID **logon_sid)
{
   DWORD err;
   TOKEN_GROUPS *grps = NULL;
   SID *sid = NULL;
   unsigned int i;

   err = read_token_info(h, TokenGroups, (void **) &grps, NULL);
   if (err)
       return err;

   for (i = 0; i < grps->GroupCount; i++) {
      if ((grps->Groups[i].Attributes & SE_GROUP_LOGON_ID) ==
		SE_GROUP_LOGON_ID) {
	  int len = GetLengthSid(grps->Groups[i].Sid);
	  SID *sid;

	  sid = (SID *) malloc(len);
	  if (!sid) {
	      err = STATUS_NO_MEMORY;
	      goto out_err;
	  }
	  if (!CopySid(len, sid, grps->Groups[i].Sid)) {
	      err = GetLastError();
	      goto out_err;
	  }
	  *logon_sid = sid;
	  sid = NULL;
	  break;
      }
   }

 out_err:
   if (sid)
       free(sid);
   if (grps)
       free(grps);
   return err;
}

struct priv_data {
    LPCTSTR name;
    bool found;
    LUID_AND_ATTRIBUTES priv;
};

/*
 * These are the only privileges, and their attributes, that we keep
 * in a non-privileged login.
 */
static struct priv_data std_privs[] = {
    { .name = SE_SHUTDOWN_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_CHANGE_NOTIFY_NAME,
      .priv = { .Attributes = SE_PRIVILEGE_ENABLED } },
    { .name = SE_UNDOCK_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_INC_WORKING_SET_NAME, .priv = { .Attributes = 0 } },
    { .name = SE_TIME_ZONE_NAME, .priv = { .Attributes = 0 } },
    {}
};

static struct priv_data *
alloc_priv_array(struct priv_data *iprivs, unsigned int *len)
{
    DWORD err;
    unsigned int i;
    struct priv_data *privs;

    for (i = 0; iprivs[i].name; i++)
	;
    privs = (struct priv_data *) malloc(i * sizeof(struct priv_data));
    if (!privs)
	return NULL;
    for (i = 0; iprivs[i].name; i++) {
	privs[i] = iprivs[i];
	if (!LookupPrivilegeValue(NULL, privs[i].name, &privs[i].priv.Luid)) {
	    free(privs);
	    return NULL;
	}
    }
    *len = i;
    return privs;
}

static bool
luid_equal(LUID a, LUID b)
{
    return a.LowPart == b.LowPart && a.HighPart == b.HighPart;
}

static DWORD
update_privileges(HANDLE h, struct priv_data *privs, unsigned int privs_len)
{
    DWORD err;
    TOKEN_PRIVILEGES *hpriv = NULL, *nhpriv = NULL;
    unsigned int i, j;

    err = read_token_info(h, TokenPrivileges, (void **) &hpriv, NULL);
    if (err)
	return err;

    nhpriv = (TOKEN_PRIVILEGES *)
	malloc(sizeof(TOKEN_PRIVILEGES) +
	       sizeof(LUID_AND_ATTRIBUTES) * (hpriv->PrivilegeCount +
					      privs_len));
    nhpriv->PrivilegeCount = hpriv->PrivilegeCount;

    for (j = 0; j < privs_len; j++)
	privs[j].found = false;
    for (i = 0; i < hpriv->PrivilegeCount; i++) {
	nhpriv->Privileges[i] = hpriv->Privileges[i];
	for (j = 0; j < privs_len; j++) {
	    if (luid_equal(nhpriv->Privileges[i].Luid, privs[j].priv.Luid)) {
		nhpriv->Privileges[i].Attributes = privs[j].priv.Attributes;
		privs[j].found = true;
		break;
	    }
	}
	if (j == privs_len)
	    /* Not found, remove it. */
	    nhpriv->Privileges[i].Attributes = SE_PRIVILEGE_REMOVED;
    }
    for (j = 0; j < privs_len; j++) {
	if (!privs[j].found)
	    nhpriv->Privileges[nhpriv->PrivilegeCount++] = privs[j].priv;
    }

    if (!AdjustTokenPrivileges(h, FALSE, nhpriv, 0, NULL, NULL)) {
	err = GetLastError();
	goto out_err;
    }
    err = 0;
 out_err:
    if (hpriv)
	free(hpriv);
    if (nhpriv)
	free(nhpriv);
    return err;
}

DWORD
medium_mandatory_policy(HANDLE h)
{
    DWORD err = 0, len = 0;
    TOKEN_MANDATORY_LABEL *integrity;
    SID *integrity_sid;

    err = read_token_info(h, TokenIntegrityLevel, (void **) &integrity, NULL);
    if (err)
	return err;

    integrity_sid = (SID *) integrity->Label.Sid;
    printf("RID was: 0x%x\n", integrity_sid->SubAuthority[0]);
    if (integrity_sid->SubAuthority[0] <= SECURITY_MANDATORY_MEDIUM_RID) {
	free(integrity);
	return 0;
    }
    integrity_sid->SubAuthority[0] = SECURITY_MANDATORY_MEDIUM_RID;

    if (!SetTokenInformation(h, TokenIntegrityLevel,
			     integrity, sizeof(integrity)))
	err = GetLastError();
    free(integrity);
    return 0;
}

struct group_list {
    const LPTSTR name;
};
static struct group_list add_groups[] = {
    { .name = TEXT("S-1-5-32-559") }, /* BUILTIN\Performance Log Users */
    { .name = TEXT("S-1-5-14") }, /* NT AUTHORITY\REMOTE INTERACTIVE LOGON */
    { .name = TEXT("S-1-5-4") }, /* NT AUTHORITY\INTERACTIVE */
    { .name = TEXT("S-1-2-0") }, /* LOCAL */
    { .name = TEXT("S-1-5-64-36") }, /* NT AUTHORITY\Cloud Account Authentication */
    { .name = TEXT("S-1-5-64-10") }, /* NT AUTHORITY\NTLM Authentication */
};
static unsigned int add_groups_len = (sizeof(add_groups) /
				      sizeof(struct group_list));

/* Supply either isid or sidstr, not both. */
static DWORD
append_group(TOKEN_GROUPS *grps, SID *isid, const LPTSTR sidstr, DWORD attrs)
{
    SID *sid = isid;
    unsigned int i = grps->GroupCount;

    if (sidstr) {
	if (!ConvertStringSidToSid(sidstr, (void **) &sid))
	    return GetLastError();
    }
    grps->Groups[i].Attributes = attrs;
    grps->Groups[i].Sid = sid;
    grps->GroupCount++;
    return 0;
}

DWORD
get_sid_from_type(WELL_KNOWN_SID_TYPE type, SID **rsid)
{
    DWORD err, len = 0;
    SID *sid;
    
    if (CreateWellKnownSid(type, NULL, NULL, &len))
	/* This should fail. */
	return ERROR_INVALID_DATA;
    err = GetLastError();
    if (err != ERROR_INSUFFICIENT_BUFFER)
	return err;
    sid = (SID *) malloc(len);
    if (!CreateWellKnownSid(type, NULL, sid, &len)) {
	err = GetLastError();
	free(sid);
	return err;
    }
    *rsid = sid;
    return 0;
}

/* FIXME - only do this for admin accounts. */
static DWORD
deny_admin_groups(HANDLE h, HANDLE *rh)
{
    DWORD err;
    HANDLE resh = NULL;
    SID *admin_sid = NULL, *admin_member_sid = NULL;
    SID_AND_ATTRIBUTES disable_sids[2];
    TOKEN_LINKED_TOKEN link;
    TOKEN_GROUPS *grps = NULL;
    unsigned int i;

    /* NT AUTHORITY\Local account and member of Administrators group */
    err = get_sid_from_type(WinNTLMAuthenticationSid, &admin_member_sid);
    if (err)
	return err;

    /* BUILTIN\Administrators */
    err = get_sid_from_type(WinBuiltinAdministratorsSid, &admin_sid);
    if (err)
	goto out_err;

    /* Check if we have admin access. */
    err = read_token_info(h, TokenGroups, (void **) &grps, NULL);
    if (err)
	goto out_err;
    for (i = 0; i < grps->GroupCount; i++) {
	if (EqualSid(admin_sid, grps->Groups[i].Sid))
	    goto is_admin;
	if (EqualSid(admin_member_sid, grps->Groups[i].Sid))
	    goto is_admin;
    }

    goto out_err;

 is_admin:

    disable_sids[0].Sid = admin_member_sid;
    disable_sids[1].Sid = admin_sid;

    if (!CreateRestrictedToken(h, 0, 2, disable_sids,
			       0, NULL, 0, NULL, &resh)) {
	err = GetLastError();
	goto out_err;
    }
#if 0 /* FIXME - why doesn't this work? */
    /*
     * Link the privileged token to the restricted one so the privileged
     * one can be used for escalation.
     */
    link.LinkedToken = h;
    if (!SetTokenInformation(resh, TokenLinkedToken, &link, sizeof(link))) {
	err = GetLastError();
	goto out_err;
    }
#endif
    err = 0;
    *rh = resh;
    resh = NULL;
 out_err:
    if (grps)
	free(grps);
    if (admin_sid)
	free(admin_sid);
    if (admin_member_sid)
	free(admin_member_sid);
    if (resh)
	CloseHandle(resh);
    return err;
}

DWORD
setup_process_token(HANDLE *inh, bool priv)
{
    DWORD err = 0;
    HANDLE newh = NULL, h = *inh;
    struct priv_data *privs = NULL;
    unsigned int privs_len;

    if (!priv) {
	err = deny_admin_groups(h, &newh);
	if (err)
	    goto out_err;
	if (newh) {
	    h = newh;
	    newh = *inh;
	}

	err = medium_mandatory_policy(h);
	if (err)
	    goto out_err;

	privs = alloc_priv_array(std_privs, &privs_len);
	if (!privs) {
	    err = STATUS_NO_MEMORY;
	    goto out_err;
	}
	err = update_privileges(h, privs, privs_len);
	if (err)
	    goto out_err;

	*inh = h;
    }
    
 out_err:
    if (privs)
	free(privs);
    if (newh)
	CloseHandle(newh);
    return err;
}

VOID
InitLsaString (
   _Out_ PLSA_STRING DestinationString,
   _In_z_ const char *szSourceString
   )
{
   USHORT StringSize;

   StringSize = (USHORT)strlen(szSourceString);

   DestinationString->Length = StringSize;
   DestinationString->MaximumLength = StringSize + sizeof(CHAR);
   DestinationString->Buffer = (PCHAR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, DestinationString->MaximumLength);

   if (DestinationString->Buffer)
   {
      memcpy(DestinationString->Buffer, szSourceString, DestinationString->Length);
   }
   else
   {
      memset(DestinationString, 0, sizeof(LSA_STRING));
   }
}

PBYTE
InitUnicodeString (
   _Out_ PUNICODE_STRING DestinationString,
   _In_z_ LPWSTR szSourceString,
   _In_ PBYTE pbDestinationBuffer
   )
{
   USHORT StringSize;

   StringSize = (USHORT)wcslen(szSourceString) * sizeof(WCHAR);
   memcpy(pbDestinationBuffer, szSourceString, StringSize);

   DestinationString->Length = StringSize;
   DestinationString->MaximumLength = StringSize + sizeof(WCHAR);
   DestinationString->Buffer = (PWSTR)pbDestinationBuffer;

   return (PBYTE)pbDestinationBuffer + StringSize + sizeof(WCHAR);
}

// NB this handler runs in a dedicated thread.
BOOL WINAPI ConsoleControlHandler(DWORD ctrlType) {
    LPCSTR ctrlTypeName;
    #define HANDLE_CONSOLE_CONTROL_EVENT(e) case e: ctrlTypeName = #e; break;
    switch (ctrlType) {
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_C_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_BREAK_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_CLOSE_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_LOGOFF_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_SHUTDOWN_EVENT)
        default:
            return FALSE;
    }
    #undef HANDLE_CONSOLE_CONTROL_EVENT
    switch (ctrlType) {
        case CTRL_CLOSE_EVENT:
        case CTRL_LOGOFF_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            return FALSE;
         default:
            return TRUE;
    }
}

int
_tmain (
   _In_ int argc,
   _In_ TCHAR *argv[]
   )
{
   int exitCode = EXIT_FAILURE;
   BOOL bResult;
   NTSTATUS Status;
   NTSTATUS SubStatus;

   HANDLE hLsa = NULL;
   HANDLE hToken = NULL;
   HANDLE hTokenS4U = NULL;

   OSVERSIONINFO osvi;
   BOOL bIsLocal = TRUE;

   LSA_STRING Msv1_0Name = { 0 };
   LSA_STRING OriginName = { 0 };
   PMSV1_0_S4U_LOGON pS4uLogon = NULL;
   MSV1_0_SET_OPTION SetOption;
   TOKEN_SOURCE TokenSource;
   ULONG ulAuthenticationPackage;
   DWORD dwMessageLength;

   PBYTE pbPosition;

   PROFILEINFO profileInfo = { 0 };
   LPVOID lpUserEnvironment = NULL;
   PROCESS_INFORMATION pi = { 0 };
   STARTUPINFO si = { 0 };

   TOKEN_GROUPS *extra_groups = NULL;
   SID *logon_sid = NULL;
   PSID pExtraSid = NULL;

   PVOID pvProfile = NULL;
   DWORD dwProfile = 0;
   LUID logonId = { 0 };
   QUOTA_LIMITS quotaLimits;

   LPTSTR szCommandLine = NULL;
   LPTSTR szSrcCommandLine = TEXT("%systemroot%\\system32\\cmd.exe /k \"whoami -all & set\"");
   LPTSTR szDomain = NULL;
   LPTSTR szUsername = NULL;
   TCHAR seps[] = TEXT("\\");
   TCHAR *next_token = NULL;
   LPCWSTR userProfileDirectory = TEXT("C:\\");
   PMSV1_0_INTERACTIVE_PROFILE pInteractiveProfile = NULL;
   unsigned int i;
   int err;
   size_t len;

   print_tokinfo(NULL);

   //
   // Ignore CTRL+C/CTRL+BREAK so we can wait for cmd.exe to handle it
   // and exit.
   //
   SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);

   g_hHeap = GetProcessHeap();

   if (argc < 2)
   {
      fprintf(stderr, "Usage:\n   s4u.exe Domain\\Username [Extra SID]\n\n");
      goto End;
   }

   //
   // Get DOMAIN and USERNAME from command line.
   //
   szDomain = _tcstok_s(argv[1], seps, &next_token);
   if (szDomain == NULL)
   {
      fprintf(stderr, "Unable to parse command line.\n");
      goto End;
   }

   szUsername = _tcstok_s(NULL, seps, &next_token);
   if (szUsername == NULL)
   {
      fprintf(stderr, "Unable to parse command line.\n");
      goto End;
   }

   //
   // Check if account is local or not
   //
   if (_tcscmp(szDomain, TEXT(".")))
      bIsLocal = FALSE;

   //
   // Get OS version
   //
   ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
   osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

#pragma warning(suppress : 4996; suppress : 28159)
   bResult = GetVersionEx(&osvi);

   if (bResult == FALSE)
   {
      fprintf(stderr, "GetVersionEx failed (error %u).\n", GetLastError());
      goto End;
   }

   //
   // Activate the required privileges
   //
   // see https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
   //
   OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
   // SeTcbPrivilege User Right: Act as part of the operating system.
   if (!SetPrivilege(hToken, SE_TCB_NAME, TRUE))
   {
      goto End;
   }
   // SeIncreaseQuotaPrivilege User Right: Adjust memory quotas for a process.
   if (!SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, TRUE))
   {
       goto End;
   }
   // SeAssignPrimaryTokenPrivilege User Right: Replace a process-level token.
   if (!SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE))
   {
       goto End;
   }

   //
   // Get logon SID
   //
   err = get_logon_sid(hToken, &logon_sid);
   if (err){
       print_err("Unable to get logon SID", err);
       goto End;
   } else if (logon_sid) {
       print_sid("logon_sid", logon_sid);
   } else {
       printf("Logon SID not present\n");
   }

   LSA_STRING name;
   LSA_OPERATIONAL_MODE dummy1;

   /* Interactive, get a token we can use for that. */
   InitLsaString(&name, "S4U");
   Status = LsaRegisterLogonProcess(&name, &hLsa, &dummy1);
   if (Status!=STATUS_SUCCESS)
   {
      fprintf(stderr, "LsaConnectUntrusted failed (error 0x%x).\n", Status);
      hLsa = NULL;
      goto End;
   }

   //
   // Lookup for the MSV1_0 authentication package (NTLMSSP)
   //
   InitLsaString(&Msv1_0Name, MSV1_0_PACKAGE_NAME);
   Status = LsaLookupAuthenticationPackage(hLsa, &Msv1_0Name, &ulAuthenticationPackage);
   if (Status!=STATUS_SUCCESS)
   {
      fprintf(stderr, "LsaLookupAuthenticationPackage failed (error 0x%x).\n", Status);
      hLsa = NULL;
      goto End;
   }

   //
   // If account is not local to your system, we must set an option to allow
   // domain account. However, the account must be in the domain accounts logon cache.
   // This option appears with Windows 8/Server 2012.
   //
   if ((!bIsLocal) && 
      ((osvi.dwMajorVersion > 6) || ((osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion > 2)))
      )
   {
      NTSTATUS ProtocolStatus;
      PVOID pvReturnBuffer = NULL;
      ULONG ulReturnBufferLength;

      //
      // Create MSV_1_0_SET_OPTION structure
      //
      memset(&SetOption, 0, sizeof(SetOption));
      SetOption.MessageType = MsV1_0SetProcessOption;
      SetOption.dwFlag = 0x20;

      dwMessageLength = sizeof(SetOption);
      
      //
      // Call LSA LsaCallAuthenticationPackage
      //
       Status = LsaCallAuthenticationPackage(
         hLsa,
         ulAuthenticationPackage,
         &SetOption,
         dwMessageLength,
         &pvReturnBuffer,
         &ulReturnBufferLength,
         &ProtocolStatus
         );
      if (Status!=STATUS_SUCCESS)
      {
         fprintf(stderr, "LsaCallAuthenticationPackage() failed (error 0x%x).\n", Status);
         goto End;
      }
   }

   //
   // Create MSV1_0_S4U_LOGON structure
   //
   dwMessageLength = (DWORD)sizeof(MSV1_0_S4U_LOGON) + (DWORD)(((DWORD)EXTRA_SID_COUNT + (DWORD)wcslen(szDomain) + (DWORD)wcslen(szUsername)) * sizeof(WCHAR));
   pS4uLogon = (PMSV1_0_S4U_LOGON)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, dwMessageLength);
   if (pS4uLogon == NULL)
   {
      fprintf(stderr, "HeapAlloc failed (error %u).\n", GetLastError());
      goto End;
   }

   pS4uLogon->MessageType = MsV1_0S4ULogon;
   pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
   pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName, szUsername, pbPosition);
   pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain, pbPosition);

   //
   // Misc
   //
   strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "S4UWin");
   InitLsaString(&OriginName, "S4U for Windows");
   AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

   //
   // Add extra SID to token.
   //
   // If the application needs to connect to a Windows Desktop, Logon SID must be added to the Token.
   //
   len = sizeof(TOKEN_GROUPS) + ((2 + add_groups_len) *
				 sizeof(SID_AND_ATTRIBUTES));
   extra_groups = (TOKEN_GROUPS *) malloc(len);
   if (!extra_groups) {
      fprintf(stderr, "Allocate extra groups failed.\n");
      goto End;
   }
   memset(extra_groups, 0, len);

   //
   // Add Logon Sid, if present.
   //
   if (logon_sid)
       append_group(extra_groups, logon_sid, NULL,
		    (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
		     SE_GROUP_MANDATORY));

   //
   // If an extra SID is specified to command line, add it to the
   // extra_groups structure.
   //
   if (argc == 3) {
       err = append_group(extra_groups, NULL, argv[2], 
			  (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
			   SE_GROUP_MANDATORY));
       if (err) {
	   print_err("Unable to add user-supplied group", err);
	   goto End;
       }
   }

   for (i = 0; i < add_groups_len; i++) {
       err = append_group(extra_groups, NULL, add_groups[i].name, 
			  (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
			   SE_GROUP_MANDATORY));
       if (err) {
	   print_err("Unable to internal user-supplied group", err);
	   goto End;
       }
   }

   //
   // Call LSA LsaLogonUser
   //
   // This call required SeTcbPrivilege privilege:
   //    - [1] to get a primary token (vs impersonation token). The privilege MUST be activated.
   //    - [2] to add supplemental SID with LocalGroups parameter.
   //    - [3] to use a username with a domain name different from machine name (or '.').
   //
   Status = LsaLogonUser(
      hLsa,
      &OriginName,
      Network,                  // Or Batch, Network
      ulAuthenticationPackage,
      pS4uLogon,
      dwMessageLength,
      extra_groups,                // LocalGroups
      &TokenSource,           // SourceContext
      &pvProfile,
      &dwProfile,
      &logonId,
      &hTokenS4U,
      &quotaLimits,
      &SubStatus
      );
   if (Status!=STATUS_SUCCESS)
   {
      printf("LsaLogonUser failed (error 0x%x).\n", Status);
      wchar_t errbuf[128];

      FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		    LsaNtStatusToWinError(Status), 0, errbuf, sizeof(errbuf), NULL);
      printf("Could not get user: %ls\n", errbuf);
      goto End;
   }

   printf("LsaLogonUser: OK, LogonId: 0x%x-0x%x\n", logonId.HighPart, logonId.LowPart);

   //
   // Load the user profile.
   //
   pInteractiveProfile = (PMSV1_0_INTERACTIVE_PROFILE)pvProfile;
   if (pInteractiveProfile->MessageType == MsV1_0InteractiveProfile)
       profileInfo.lpServerName = pInteractiveProfile->LogonServer.Buffer;
   profileInfo.dwSize = sizeof(profileInfo);
   profileInfo.dwFlags = PI_NOUI;
   profileInfo.lpUserName = szUsername;
   if (!LoadUserProfile(hTokenS4U, &profileInfo))
   {
        fprintf(stderr, "LoadUserProfile failed (error %u).\n", GetLastError());
        goto End;
   }

   //
   // Load the user environment variables.
   //
   if (!CreateEnvironmentBlock(&lpUserEnvironment, hTokenS4U, FALSE))
   {
       fprintf(stderr, "CreateEnvironmentBlock failed (error %u).\n", GetLastError());
       goto End;
   }

   err = setup_process_token(&hTokenS4U, false);
   //
   // Create process with S4U token.
   //
   si.cb = sizeof(STARTUPINFO);
   si.lpDesktop = TEXT("winsta0\\default");

   //
   // Warning: szCommandLine parameter of CreateProcessAsUser() must be writable
   //
   szCommandLine = (LPTSTR)HeapAlloc(g_hHeap, HEAP_ZERO_MEMORY, MAX_PATH * sizeof(TCHAR));
   if (szCommandLine == NULL)
   {
      fprintf(stderr, "HeapAlloc failed (error %u).\n", GetLastError());
      goto End;
   }

   if (ExpandEnvironmentStrings(szSrcCommandLine, szCommandLine, MAX_PATH) == 0)
   {
      fprintf(stderr, "ExpandEnvironmentStrings failed (error %u).\n", GetLastError());
      goto End;
   }

   //
   // Get the User Profile directory.
   //
   // NB we could also have used the GetUserProfileDirectory function; but
   //    this way we do not have to deal with memory allocation.
   //
   for (LPCWSTR env = (LPCWSTR)lpUserEnvironment; *env; env += wcslen(env) + 1)
   {
       if (!(wcsncmp(env, L"USERPROFILE=", wcslen(L"USERPROFILE="))))
       {
           userProfileDirectory = env + wcslen(L"USERPROFILE=");
           break;
       }
   }

   HANDLE tmph;
   if (!DuplicateTokenEx(hTokenS4U,
			 TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
			 NULL, SecurityAnonymous, TokenPrimary, &tmph)) {
       print_err("Duplicate token", GetLastError());
       goto End;
   }
   CloseHandle(hTokenS4U);
   hTokenS4U = tmph;
   
   print_tokinfo(hTokenS4U);

   //
   // CreateProcessAsUser requires these privileges to be available in the current process:
   //
   //   SeTcbPrivilege (must be Enabled)
   //   SeAssignPrimaryTokenPrivilege (can be Disabled, will be automatically Enabled)
   //   SeIncreaseQuotaPrivilege (can be Disabled, will be automatically Enabled)
   //
   bResult = CreateProcessAsUser(
      hTokenS4U,
      NULL,
      szCommandLine,
      NULL,
      NULL,
      FALSE,
      NORMAL_PRIORITY_CLASS | CREATE_UNICODE_ENVIRONMENT,
      lpUserEnvironment,
      userProfileDirectory,
      &si,
      &pi
      );
   if (bResult == FALSE)
   {
      fprintf(stderr, "CreateProcessAsUser failed (error %u).\n", GetLastError());
      goto End;
   }

   exitCode = EXIT_SUCCESS;

End:
   //
   // Free resources
   //
   if (Msv1_0Name.Buffer)
      HeapFree(g_hHeap, 0, Msv1_0Name.Buffer);
   if (OriginName.Buffer)
      HeapFree(g_hHeap, 0, OriginName.Buffer);
   if (logon_sid)
       free(logon_sid);
   if (pExtraSid)
      LocalFree(pExtraSid);
   if (pS4uLogon)
      HeapFree(g_hHeap, 0, pS4uLogon);
   if (extra_groups)
      free(extra_groups);
   if (pvProfile)
      LsaFreeReturnBuffer(pvProfile);
   if (hLsa)
      LsaClose(hLsa);
   if (lpUserEnvironment)
      DestroyEnvironmentBlock(lpUserEnvironment);
   if (profileInfo.hProfile)
      UnloadUserProfile(hTokenS4U, profileInfo.hProfile);
   if (hToken)
      CloseHandle(hToken);
   if (hTokenS4U)
      CloseHandle(hTokenS4U);
   if (pi.hThread)
      CloseHandle(pi.hThread);
   if (pi.hProcess)
   {
      WaitForSingleObject(pi.hProcess, INFINITE);
      CloseHandle(pi.hProcess);
   }

   return exitCode;
}
