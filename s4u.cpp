/*
 * WARNING - this program is a hack, it does not do proper password
 * handling and you should, of course, never pass in passwords on the
 * command line in a production program.
 */

#include <Windows.h>
#include <Ntsecapi.h>
#include <UserEnv.h>
#include <aclapi.h>
#include <accctrl.h>
#include <wtsapi32.h>
#include <ntdef.h>
#include <psapi.h>
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

static void
print_err(const char *str, DWORD err)
{
      wchar_t errbuf[128];

      FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		    err, 0, errbuf, sizeof(errbuf), NULL);
      fprintf(stderr, "error: %s (0x%lx): %ls\n", str, err, errbuf);
}

static void
pr_err(int indent, const char *str, DWORD err)
{
      wchar_t errbuf[128];

      FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, NULL,
		    err, 0, errbuf, sizeof(errbuf), NULL);
      printf("%*s%s: ***fetch error: (0x%lx): %ls",
	     indent, "", str, err, errbuf);
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
    printf("%*s%s:\n", indent, "", str);
    pr_sid(indent + 2, "Sid", (SID *) v->Sid);
    printf("%*sAttributes: 0x%lx\n", indent + 2, "", v->Attributes);
}

static void
pr_sid_attr_hash(int indent, const char *str, SID_AND_ATTRIBUTES_HASH *v)
{
    DWORD i;
    char buf[100];

    printf("%*s%s:\n", indent, "", str);
    printf("%*sSidCount: %ld\n", indent + 2, "", v->SidCount);
    for (i = 0; i < v->SidCount; i++) {
	snprintf(buf, sizeof(buf), "SidAttr[%ld]", i);
	pr_sid_attr(indent + 2, buf, &v->SidAttr[i]);
    }
    for (i = 0; i < SID_HASH_SIZE; i++) {
	printf("%*sHash[%ld]: 0x%llx\n", indent + 2, "", i, v->Hash[i]);
    }
}

void
pr_luid(int indent, const char *str, LUID *v)
{
    char name[100] = "";
    DWORD len = sizeof(name);
    LookupPrivilegeNameA(NULL, v, name, &len);
    printf("%*s%s: '%s' %ld:%ld\n", indent, "", str, name,
	   v->LowPart, v->HighPart);
}

void
pr_luid_and_attr(int indent, const char *str, LUID_AND_ATTRIBUTES *v)
{
    printf("%*s%s:\n", indent, "", str);
    pr_luid(indent + 2, "Luid", &v->Luid);
    printf("%*sAttributes: 0x%lx\n", indent + 2, "", v->Attributes);
}

void
pr_guid(int indent, const char *str, GUID *v)
{
    printf("%*s%s: %ld:%d:%d:%d:%d:%d:%d:%d:%d:%d:%d\n", indent, "", str,
	   v->Data1, v->Data2, v->Data3, v->Data4[0], v->Data4[1],
	   v->Data4[2], v->Data4[3], v->Data4[4], v->Data4[5],
	   v->Data4[6], v->Data4[7]);
}

void
pr_token_priv(int indent, const char *str, TOKEN_PRIVILEGES *v)
{
    DWORD i;
    char buf[100];

    printf("%*s%s:\n", indent, "", str);
    printf("%*sPrivilegeCount: %ld\n", indent + 2, "", v->PrivilegeCount);
    for (i = 0; i < v->PrivilegeCount; i++) {
	snprintf(buf, sizeof(buf), "Privileges[%ld]", i);
	pr_luid_and_attr(indent + 2, "", &v->Privileges[i]);
    }
}

static void
pr_ace(int indent, const char *str, ACE_HEADER *v)
{
    printf("%*s%s:\n", indent, "", str);
    printf("%*sType: %d\n", indent + 2, "", v->AceType);
    printf("%*sFlags: 0x%x\n", indent + 2, "", v->AceFlags);
    printf("%*sSize: %d\n", indent + 2, "", v->AceSize);
    switch(v->AceType) {
    /* ACCESS_MIN_MS_ACE_qTYPE */
    case ACCESS_ALLOWED_ACE_TYPE: {
	ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *) v;
	printf("%*sACCESS_ALLOWED:\n", indent + 2, "");
	
	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_ALLOWED_CALLBACK_ACE_TYPE: {
	ACCESS_ALLOWED_CALLBACK_ACE *a = (ACCESS_ALLOWED_CALLBACK_ACE *) v;
	printf("%*sACCESS_ALLOWED_CALLBACK:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: {
	ACCESS_ALLOWED_CALLBACK_OBJECT_ACE *a =
	    (ACCESS_ALLOWED_CALLBACK_OBJECT_ACE *) v;
	printf("%*sACCESS_ALLOWED_CALLBACK_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    /* case ACCESS_ALLOWED_COMPOUND_ACE_TYPE: */

    /* ACCESS_MIN_MS_OBJECT_ACE_TYPE */
    case ACCESS_ALLOWED_OBJECT_ACE_TYPE: {
	ACCESS_ALLOWED_OBJECT_ACE *a = (ACCESS_ALLOWED_OBJECT_ACE *) v;
	printf("%*sACCESS_ALLOWED_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_DENIED_ACE_TYPE: {
	ACCESS_DENIED_ACE *a = (ACCESS_DENIED_ACE *) v;
	printf("%*sACCESS_DENIED:\n", indent + 2, "");
	
	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_DENIED_CALLBACK_ACE_TYPE: {
	ACCESS_DENIED_CALLBACK_ACE *a = (ACCESS_DENIED_CALLBACK_ACE *) v;
	printf("%*sACCESS_DENIED_CALLBACK:\n", indent + 2, "");
	
	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: {
	ACCESS_DENIED_CALLBACK_OBJECT_ACE *a =
	    (ACCESS_DENIED_CALLBACK_OBJECT_ACE *) v;
	printf("%*sACCESS_DENIED_CALLBACK_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case ACCESS_DENIED_OBJECT_ACE_TYPE: {
	ACCESS_DENIED_OBJECT_ACE *a = (ACCESS_DENIED_OBJECT_ACE *) v;
	printf("%*sACCESS_DENIED_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    /* case ACCESS_MAX_MS_V2_ACE_TYPE: */
    case SYSTEM_ALARM_ACE_TYPE: {
	SYSTEM_ALARM_ACE *a = (SYSTEM_ALARM_ACE *) v;
	printf("%*sSYSTEM_ALARM:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    /* case ACCESS_MAX_MS_V4_ACE_TYPE: */
    /* case ACCESS_MAX_MS_OBJECT_ACE_TYPE: */
    case SYSTEM_ALARM_CALLBACK_ACE_TYPE: {
	SYSTEM_ALARM_CALLBACK_ACE *a = (SYSTEM_ALARM_CALLBACK_ACE *) v;
	printf("%*sSYSTEM_ALARM_CALLBACK:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE: {
	SYSTEM_ALARM_CALLBACK_OBJECT_ACE *a =
	    (SYSTEM_ALARM_CALLBACK_OBJECT_ACE *) v;
	printf("%*sSYSTEM_ALARM_CALLBACK_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    /* case ACCESS_MAX_MS_V3_ACE_TYPE: */

    /* case ACCESS_MAX_MS_ACE_TYPE: */
    case SYSTEM_ALARM_OBJECT_ACE_TYPE: {
	SYSTEM_ALARM_OBJECT_ACE *a = (SYSTEM_ALARM_OBJECT_ACE *) v;
	printf("%*sSYSTEM_ALARM_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_AUDIT_ACE_TYPE: {
	SYSTEM_AUDIT_ACE *a = (SYSTEM_AUDIT_ACE *) v;
	printf("%*sSYSTEM_AUDIT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_AUDIT_CALLBACK_ACE_TYPE: {
	SYSTEM_AUDIT_CALLBACK_ACE *a = (SYSTEM_AUDIT_CALLBACK_ACE *) v;
	printf("%*sSYSTEM_AUDIT_CALLBACK:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE: {
	SYSTEM_AUDIT_CALLBACK_OBJECT_ACE *a =
	    (SYSTEM_AUDIT_CALLBACK_OBJECT_ACE *) v;
	printf("%*sSYSTEM_AUDIT_CALLBACK_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_AUDIT_OBJECT_ACE_TYPE: {
	SYSTEM_AUDIT_OBJECT_ACE *a = (SYSTEM_AUDIT_OBJECT_ACE *) v;
	printf("%*sSYSTEM_AUDIT_OBJECT:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	printf("%*sFlags: %lx\n", indent + 4, "", a->Flags);
	pr_guid(indent + 4, "ObjectType", &a->ObjectType);
	pr_guid(indent + 4, "InheritedObjectType", &a->InheritedObjectType);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    case SYSTEM_MANDATORY_LABEL_ACE_TYPE: {
	SYSTEM_MANDATORY_LABEL_ACE *a = (SYSTEM_MANDATORY_LABEL_ACE *) v;
	printf("%*sSYSTEM_MANDATORY_LABEL:\n", indent + 2, "");

	printf("%*sMask: %lx\n", indent + 4, "", a->Mask);
	pr_sid(indent + 4, "SID", (SID *) &a->SidStart);
	break;
    }

    default:
	printf("%*sUnknown ACE type\n", indent + 2, "");
	break;
    }
}

static void
pr_acl(int indent, const char *str, ACL *v)
{
    unsigned int i;
    ACL_REVISION_INFORMATION r;
    ACL_SIZE_INFORMATION s;
    char buf[100];

    printf("%*s%s:\n", indent, "", str);
    if (!GetAclInformation(v, &r, sizeof(r), AclRevisionInformation)) {
	printf("%*sRevision: **Error fetching: %ld\n", indent + 2, "",
	       GetLastError());
    } else {
	printf("%*sRevision: %ld\n", indent + 2, "", r.AclRevision);
    }
    if (!GetAclInformation(v, &s, sizeof(s), AclSizeInformation)) {
	printf("%*sSize: **Error fetching: %ld\n", indent + 2, "",
	       GetLastError());
	return;
    } else {
	printf("%*sAceCount: %ld\n", indent + 2, "", s.AceCount);
	printf("%*sBytesInUse: %ld\n", indent + 2, "", s.AclBytesInUse);
	printf("%*sBytesFree: %ld\n", indent + 2, "", s.AclBytesFree);
    }

    for (i = 0; i < s.AceCount; i++) {
	ACE_HEADER *a;

	snprintf(buf, sizeof(buf), "Ace[%d]", i);
	if (!GetAce(v, i, (void **) &a)) {
	    printf("%*s%s: **Error fetching: %ld\n", indent + 4, "", buf,
		   GetLastError());
	    continue;
	}
	pr_ace(indent + 4, buf, a);
    }
}

static void
pr_token_groups(int indent, const char *str, TOKEN_GROUPS *v)
{
    DWORD i;
    char buf[100];

    printf("%*s%s:\n", indent, "", str);
    for (i = 0; i < v->GroupCount; i++) {
	snprintf(buf, sizeof(buf), "Group[%ld]", i);
	pr_sid_attr(2, buf, &v->Groups[i]);
    }
}

static void
pr_token_groups_and_privileges(int indent, const char *str,
			       TOKEN_GROUPS_AND_PRIVILEGES *v)
{
    DWORD i;
    char buf[100];

    printf("%*s%s:\n", indent, "", str);
    printf("%*sSidCount: %ld\n", indent + 2, "", v->SidCount);
    printf("%*sSidLength: %ld\n", indent + 2, "", v->SidLength);
    for (i = 0; i < v->SidCount; i++) {
	snprintf(buf, sizeof(buf), "Sids[%ld]", i);
	pr_sid_attr(indent + 2, buf, &v->Sids[i]);
    }
    printf("%*sRestrictedSidCount: %ld\n", indent + 2, "",
	   v->RestrictedSidCount);
    printf("%*sRestrictedSidLength: %ld\n", indent + 2, "",
	   v->RestrictedSidLength);
    for (i = 0; i < v->RestrictedSidCount; i++) {
	snprintf(buf, sizeof(buf), "RestrictedSids[%ld]", i);
	pr_sid_attr(indent + 2, buf, &v->RestrictedSids[i]);
    }
    printf("%*sPrivilegeCount: %ld\n", indent + 2, "",
	   v->PrivilegeCount);
    printf("%*sPrivilegeLength: %ld\n", indent + 2, "",
	   v->PrivilegeLength);
    for (i = 0; i < v->PrivilegeCount; i++) {
	snprintf(buf, sizeof(buf), "Privileges[%ld]", i);
	pr_luid_and_attr(indent + 2, buf, &v->Privileges[i]);
    }
    pr_luid(indent + 2, "AuthenticationId", &v->AuthenticationId);
}

static void
pr_token_source(int indent, const char *str, TOKEN_SOURCE *v)
{
    printf("%*s%s:\n", indent, "", str);
    printf("%*sSourceName: %s\n", indent + 2, "", v->SourceName);
    pr_luid(indent + 2, "SourceIdentifier", &v->SourceIdentifier);
}

static void
pr_tok_mand_pol(int indent, const char *str, TOKEN_MANDATORY_POLICY *v)
{
    printf("%*s%s.Policy: %ld\n", indent, "", str, v->Policy);
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

static void
pr_token_statistics(int indent, HANDLE h, const char *str)
{
    DWORD err;
    TOKEN_STATISTICS *v;

    printf("%*s%s:\n", indent, "", str);
    err = read_token_info(h, TokenStatistics, (void **) &v, NULL);
    if (err) {
	pr_err(indent + 2, "**Fetch error", err);
	return;
    }

    pr_luid(indent + 2, "Token Id", &v->TokenId);
    pr_luid(indent + 2, "Authentication Id", &v->AuthenticationId);
    printf("%*sExpiraton Time: %lld\n", indent + 2, "",
	   v->ExpirationTime.QuadPart);
    printf("%*sImpersonation level: %d\n", indent + 2, "",
	   v->ImpersonationLevel);
    printf("%*sDynamicCharged: %ld\n", indent + 2, "", v->DynamicCharged);
    printf("%*sDynamicAvailable: %ld\n", indent + 2, "", v->DynamicAvailable);
    printf("%*sGroupCount: %ld\n", indent + 2, "", v->GroupCount);
    printf("%*sPrivilege count: %ld\n", indent + 2, "", v->PrivilegeCount);
    pr_luid(indent + 2, "Modified Id", &v->ModifiedId);
    free(v);
}

DWORD
print_security_info(HANDLE h)
{
    DWORD err;
    SID *owner = NULL, *group = NULL;
    SECURITY_DESCRIPTOR *secdesc = NULL;

    err = GetSecurityInfo(h, SE_KERNEL_OBJECT,
			  (OWNER_SECURITY_INFORMATION |
			   GROUP_SECURITY_INFORMATION),
			  (void **) &owner, (void **) &group,
			  NULL, NULL, (void **) &secdesc);
    if (err) {
	print_err("GetSecurityInfo", err);
	return err;
    }
    print_sid("Owner", owner);
    print_sid("Group", group);
    if (secdesc)
	LocalFree(secdesc);
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

static void
pr_token_access_info(int indent, HANDLE h)
{
    DWORD err;
    struct ta2 *access_info;

    printf("%*sAccess info:\n", indent, "");
    err = read_token_info(h, TokenAccessInformation, (void **) &access_info,
			  NULL);
    if (err) {
	pr_err(indent + 2, "Access info", err);
    } else {
	pr_sid_attr_hash(indent + 2, "SidHash", access_info->SidHash);
	pr_sid_attr_hash(indent + 2, "RestrictedSidHash",
			 access_info->RestrictedSidHash);
	pr_token_priv(indent + 2, "Privileges", access_info->Privileges);
	pr_luid(indent + 2, "AuthenticationId",
		&access_info->AuthenticationId);
	printf("%*sTokenType: %d\n", indent + 2, "", access_info->TokenType);
	printf("%*sImpersonationLevel: %d\n", indent + 2, "",
	       access_info->ImpersonationLevel);
	pr_tok_mand_pol(indent + 2, "MandatoryPolicy",
			&access_info->MandatoryPolicy);
	printf("%*sFlags: %ld\n", indent + 2, "", access_info->Flags);
	printf("%*sAppContainerNumber: %ld\n", indent + 2, "",
	       access_info->AppContainerNumber);
	pr_sid(indent + 2, "PackageSid", (SID *) access_info->PackageSid);
	pr_sid_attr_hash(indent + 2, "CapabilitiesHash",
			 access_info->CapabilitiesHash);
	pr_sid(indent + 2, "TrustLevelSid",
	       (SID *) access_info->TrustLevelSid);
	free(access_info);
    }
}

static DWORD
get_dword_tokinfo(HANDLE h, TOKEN_INFORMATION_CLASS type, DWORD *val)
{
    DWORD len = sizeof(DWORD);

    if (!GetTokenInformation(h, type, val, len, &len))
	return GetLastError();
    return 0;
}

static void
pr_dword_tokinfo(int indent, bool hex,
		 HANDLE h, TOKEN_INFORMATION_CLASS type, const char *str)
{
    DWORD val, err;

    err = get_dword_tokinfo(h, type, &val);
    if (err)
	pr_err(indent, str, err);
    else if (hex)
	printf("%*s%s: 0x%lx\n", indent, "", str, val);
    else
	printf("%*s%s: %lu\n", indent, "", str, val);
}

static void
pr_int_tokinfo(int indent,
	       HANDLE h, TOKEN_INFORMATION_CLASS type, const char *str)
{
    int val;
    DWORD len = sizeof(val);

    if (!GetTokenInformation(h, type, &val, len, &len))
	pr_err(indent, str, GetLastError());
    else
	printf("%*s%s: %d\n", indent, "", str, val);
}

static void
print_tokinfo(HANDLE inh)
{
    HANDLE h;
    DWORD err;

    if (inh) {
	h = inh;
    } else {
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h)) {
	    print_err("OpenProcessToken", GetLastError());
	    return;
	}
    }

    TOKEN_USER *user;
    err = read_token_info(h, TokenUser, (void **) &user, NULL);
    if (err) {
	pr_err(0, "Get Token user", err);
    } else {
	pr_sid_attr(0, "Token user", &user->User);
	free(user);
    }
    
    TOKEN_GROUPS *groups;
    err = read_token_info(h, TokenGroups, (void **) &groups, NULL);
    if (err) {
	pr_err(0, "Get Token groups", err);
    } else {
	pr_token_groups(0, "Token groups", groups);
	free(groups);
    }

    TOKEN_PRIVILEGES *privs;
    err = read_token_info(h, TokenPrivileges, (void **) &privs, NULL);
    if (err) {
	pr_err(0, "Get Token privileges", err);
    } else {
	pr_token_priv(0, "Token privileges", privs);
	free(privs);
    }

    TOKEN_OWNER *owner;
    err = read_token_info(h, TokenOwner, (void **) &owner, NULL);
    if (err) {
	pr_err(0, "Get Token owner", err);
    } else {
	pr_sid(0, "Token owner", (SID *) owner->Owner);
	free(owner);
    }
    
    TOKEN_PRIMARY_GROUP *pgroup;
    err = read_token_info(h, TokenPrimaryGroup, (void **) &pgroup, NULL);
    if (err) {
	pr_err(0,"Get Token primary group", err);
    } else {
	pr_sid(0, "Token primary group", (SID *) pgroup->PrimaryGroup);
	free(pgroup);
    }
    
    TOKEN_DEFAULT_DACL *ddacl;
    err = read_token_info(h, TokenDefaultDacl, (void **) &ddacl, NULL);
    if (err) {
	pr_err(0, "Get Token default dacl", err);
    } else {
	pr_acl(0, "Token default dacl", ddacl->DefaultDacl);
	free(ddacl);
    }
    
    TOKEN_SOURCE *source;
    err = read_token_info(h, TokenSource, (void **) &source, NULL);
    if (err) {
	pr_err(0, "Token source", err);
    } else {
	pr_token_source(0, "Token source", source);
	free(source);
    }

    pr_int_tokinfo(0, h, TokenType, "Token type");
    pr_int_tokinfo(0, h, TokenImpersonationLevel, "Impersonation level");
    pr_token_statistics(0, h, "Token statistics");

    err = read_token_info(h, TokenRestrictedSids, (void **) &groups, NULL);
    if (err) {
	pr_err(0, "Token restricted sids", err);
    } else {
	pr_token_groups(0, "Token restricted sids", groups);
	free(groups);
    }

    pr_dword_tokinfo(0, false, h, TokenSessionId, "Session Id");

    TOKEN_GROUPS_AND_PRIVILEGES *grpriv;
    err = read_token_info(h, TokenGroupsAndPrivileges, (void **) &grpriv,
			  NULL);
    if (err) {
	pr_err(0, "Token groups and privileges", err);
    } else {
	pr_token_groups_and_privileges(0, "Token groups and privileges",
				       grpriv);
	free(grpriv);
    }

    pr_dword_tokinfo(0, false, h, TokenSandBoxInert, "Token sandbox inert");

    pr_dword_tokinfo(0, false, h, TokenUIAccess, "Token UI access");
    pr_dword_tokinfo(0, false, h, TokenIsAppContainer,
		     "Token is App Container");
    pr_dword_tokinfo(0, false, h, TokenMandatoryPolicy,
		     "Token mandatory policy");

    pr_token_access_info(0, h);

    if (!inh)
	CloseHandle(h);

    print_security_info(h);
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
	print_err("LookupPrivilegeValue", GetLastError());
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
    if (!AdjustTokenPrivileges(hToken,
			       FALSE,
			       &tp,
			       sizeof(TOKEN_PRIVILEGES),
			       (PTOKEN_PRIVILEGES)NULL,
			       (PDWORD)NULL)) {
	print_err("AdjustTokenPrivileges", GetLastError());
	return FALSE;
    } else {
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
	    fprintf(stderr,
		    "The token does not have the specified privilege (%S).\n",
		    lpszPrivilege);
	    return FALSE;
	}
    }

    return TRUE;
}

DWORD
set_privileges(HANDLE hToken)
{
    //
    // Activate the required privileges
    //
    // see https://docs.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
    //
    // SeTcbPrivilege User Right: Act as part of the operating system.
    if (!SetPrivilege(hToken, SE_TCB_NAME, TRUE)) {
	goto End;
    }
    // SeIncreaseQuotaPrivilege User Right: Adjust memory quotas for a process.
    if (!SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, TRUE)) {
	goto End;
    }
    // SeAssignPrimaryTokenPrivilege User Right: Replace a process-level token.
    if (!SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE)) {
	goto End;
    }

    // SeImpersonatePrivilege User Right
    if (!SetPrivilege(hToken, SE_IMPERSONATE_NAME, TRUE)) {
	goto End;
    }

#if 0
    /*
     * Can't get seCreateTokenPrivilege this way, have to impersonate
     * lsass.exe.
     */
    if (!SetPrivilege(hToken, SE_CREATE_TOKEN_NAME, TRUE)) {
	goto End;
    }
#endif
    if (!SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, TRUE)) {
	goto End;
    }
    if (!SetPrivilege(hToken, SE_SECURITY_NAME, TRUE)) {
	goto End;
    }
    return 0;
 End:
    return GetLastError();
}

DWORD
find_sessions(void)
{
    DWORD err, sescount;
    WTS_SESSION_INFOA *sesinfo;
    unsigned int i;
    HANDLE h;

    if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
			       &sesinfo, &sescount)) {
	err = GetLastError();
	print_err("WTSEnumerateSessionsA", err);
	return err;
    }

    for (i = 0; i < sescount; i++) {
	printf("Session %d: %ld '%s' %d\n", i, sesinfo[i].SessionId,
	       sesinfo[i].pWinStationName, sesinfo[i].State);
	if (!WTSQueryUserToken(sesinfo[i].SessionId, &h)) {
	    print_err("WTSQueryUserToken", GetLastError());
	} else {
	    printf("Got handle\n");
	    CloseHandle(h);
	}
    }
    WTSFreeMemory(sesinfo);
    return 0;
}

DWORD
get_logon_sid(HANDLE h, SID **logon_sid)
{
    DWORD err;
    TOKEN_GROUPS *grps = NULL;
    SID *sid = NULL;
    unsigned int i;
    bool found = false;
    WTS_SESSION_INFOA *sesinfo = NULL;
    DWORD sescount, sescur = 0;;

 retry:
   err = read_token_info(h, TokenGroups, (void **) &grps, NULL);
   if (err)
       return err;

   for (i = 0; i < grps->GroupCount; i++) {
      if ((grps->Groups[i].Attributes & SE_GROUP_LOGON_ID) ==
		SE_GROUP_LOGON_ID) {
	  int len = GetLengthSid(grps->Groups[i].Sid);

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
	  found = true;
	  break;
      }
   }

   /*
    * No logon sid was found in our token, find a user who has it.
    */
   if (!found) {
   retry2:
       if (!sesinfo) {
	   if (!WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1,
				  &sesinfo, &sescount)) {
	       err = GetLastError();
	       print_err("WTSEnumerateSessionsA", err);
	       goto out_err;
	   }
       } else {
	   sescur++;
       }
       if (sescur >= sescount) {
	   err = 0;
	   goto out_err;
       }

       if (sescur > 0)
	   CloseHandle(h);
       if (!WTSQueryUserToken(sesinfo[sescur].SessionId, &h)) {
	   goto retry2;
       } else {
	   goto retry;
       }
   }

 out_err:
   if (sescur > 0)
       CloseHandle(h);
   if (sesinfo)
       WTSFreeMemory(sesinfo);
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
    DWORD err = 0;
    TOKEN_MANDATORY_LABEL *integrity;
    SID *integrity_sid;

    err = read_token_info(h, TokenIntegrityLevel, (void **) &integrity, NULL);
    if (err)
	return err;

    integrity_sid = (SID *) integrity->Label.Sid;
    //printf("RID was: 0x%x\n", integrity_sid->SubAuthority[0]);
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
InitLsaString(PLSA_STRING DestinationString,
	      const char *szSourceString)
{
   USHORT StringSize;

   StringSize = (USHORT)strlen(szSourceString);

   DestinationString->Length = StringSize;
   DestinationString->MaximumLength = StringSize + sizeof(CHAR);
   DestinationString->Buffer = (PCHAR) malloc(DestinationString->MaximumLength);

   if (DestinationString->Buffer) {
      memcpy(DestinationString->Buffer, szSourceString,
	     DestinationString->Length);
   } else {
      memset(DestinationString, 0, sizeof(LSA_STRING));
   }
}

PBYTE
InitUnicodeString (PUNICODE_STRING DestinationString,
		   LPWSTR szSourceString,
		   PBYTE pbDestinationBuffer)
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
#if 0
    LPCSTR ctrlTypeName;
#endif

#define HANDLE_CONSOLE_CONTROL_EVENT(e) case e: ctrlTypeName = #e; break;
    switch (ctrlType) {
#if 0
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_C_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_BREAK_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_CLOSE_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_LOGOFF_EVENT)
        HANDLE_CONSOLE_CONTROL_EVENT(CTRL_SHUTDOWN_EVENT)
#endif
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

#if 0
DWORD
find_lsass_tok(HANDLE *rtok)
{
    DWORD *processes, len = 1000, newlen, count, err = 0, i;
    LUID luid;
    bool found = false;
    HANDLE tokh = NULL;

    if (!LookupPrivilegeValue(NULL, SE_CREATE_TOKEN_NAME, &luid))
	return GetLastError();

 restart:
    processes = (DWORD *) malloc(len);
    if (!processes)
	return STATUS_NO_MEMORY;
    if (!EnumProcesses(processes, len, &newlen))
	return GetLastError();
    if (len == newlen) {
	/* May not have gotten all the processes, try again. */
	free(processes);
	len += 1000;
	goto restart;
    }

    count = len / sizeof(DWORD);
    for (i = 0; !found && i < count; i++) {
	HANDLE proch = OpenProcess(PROCESS_QUERY_INFORMATION |
				   PROCESS_VM_READ,
				   FALSE, processes[i]);
        HMODULE modh;
	TOKEN_PRIVILEGES *hpriv = NULL;
	char procname[MAX_PATH];
	unsigned int j;

	if (!proch)
	    continue;

        if (!EnumProcessModules(proch, &modh, sizeof(modh), &len))
	    goto nextproc;

	if (!GetModuleBaseNameA(proch, modh, procname, sizeof(procname)))
	    goto nextproc;

	if (strcmp(procname, "lsass.exe") != 0)
	    goto nextproc;

	if (!OpenProcessToken(proch, TOKEN_ALL_ACCESS, &tokh))
	    goto nextproc;

	err = read_token_info(tokh, TokenPrivileges, (void **) &hpriv, NULL);
	if (err)
	    goto nextproc;

	for (j = 0; j < hpriv->PrivilegeCount; j++) {
	    if (luid_equal(hpriv->Privileges[j].Luid, luid))
		found = true;
	}

    nextproc:
	CloseHandle(proch);
	if (!found && tokh) {
	    CloseHandle(tokh);
	    tokh = NULL;
	}
	if (hpriv)
	    free(hpriv);
    }

    err = 0;
    if (tokh) {
	if (!DuplicateToken(tokh, SecurityImpersonation, rtok))
	    err = GetLastError();
	CloseHandle(tokh);
	return err;
    }

    return ERROR_PROC_NOT_FOUND;
}

typedef NTSTATUS (*NtCreateToken)(
       PHANDLE TokenHandle,
       ACCESS_MASK DesiredAccess,
       POBJECT_ATTRIBUTES ObjectAttributes,
       TOKEN_TYPE TokenType,
       PLUID AuthenticationId,
       PLARGE_INTEGER ExpirationTime,
       PTOKEN_USER User,
       PTOKEN_GROUPS Groups,
       PTOKEN_PRIVILEGES Privileges,
       PTOKEN_OWNER Owner,
       PTOKEN_PRIMARY_GROUP PrimaryGroup,
       PTOKEN_DEFAULT_DACL DefaultDacl,
       PTOKEN_SOURCE TokenSource);

static DWORD
create_token_from_existing_token(HANDLE logon_tok, HANDLE *htok)
{
    NTSTATUS Status;
    DWORD err = 0;
    HMODULE hModule;
    NtCreateToken CreateToken;
    TOKEN_STATISTICS tstats;
    DWORD ilen;
    LUID session_id;
    TOKEN_USER *user;
    TOKEN_GROUPS *groups;
    TOKEN_PRIVILEGES *privileges;
    TOKEN_PRIMARY_GROUP *primary_group;
    TOKEN_DEFAULT_DACL *default_dacl;
    TOKEN_OWNER owner;
    SECURITY_QUALITY_OF_SERVICE sqos;
    OBJECT_ATTRIBUTES oa;
    HANDLE lstok;
    TOKEN_SOURCE TokenSource;

    /* FIXME - nothing is cleaned up here. */

    hModule = GetModuleHandle(TEXT("ntdll.dll"));
    if (!hModule) {
	err = GetLastError();
	print_err("GetModuleHandle", err);
	goto End;
    }
    CreateToken = (NtCreateToken)GetProcAddress(hModule, "NtCreateToken");
    if (!CreateToken) {
	err = GetLastError();
	print_err("GetProcAddress", err);
	goto End;
    }

    if (!GetTokenInformation(logon_tok, TokenStatistics,
			     &tstats, sizeof(tstats), &ilen)) {
	err = GetLastError();
	print_err("GetTokenInformation", err);
	goto End;
    }
    session_id = ANONYMOUS_LOGON_LUID;
    //AllocateLocallyUniqueId(&session_id);

    err = read_token_info(logon_tok, TokenUser, (void **) &user, NULL);
    if (err) {
	print_err("Get token user", err);
	goto End;
    }

    err = read_token_info(logon_tok, TokenGroups, (void **) &groups, NULL);
    if (err) {
	print_err("Get token user", err);
	goto End;
    }

    err = read_token_info(logon_tok, TokenPrivileges,
			  (void **) &privileges, NULL);
    if (err) {
	print_err("Get token privileges", err);
	goto End;
    }

    err = read_token_info(logon_tok, TokenPrimaryGroup,
			  (void **) &primary_group, NULL);
    if (err) {
	print_err("Get token primary group", err);
	goto End;
    }

    err = read_token_info(logon_tok, TokenDefaultDacl,
			  (void **) &default_dacl, NULL);
    if (err) {
	print_err("Get token default dacl", err);
	goto End;
    }

    owner.Owner = user->User.Sid;

    sqos = {
	sizeof(sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING
    };
    oa = {
	sizeof(oa), 0, 0, 0, 0, &sqos
    };

    strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "S4UWin");
    AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

    /*
     * The lsass.exe process has the necessary seCreateTokenPrivilege
     * required to run NtCreateToken.  That is apparently the only way
     * to get this privilege.
     */
    err = find_lsass_tok(&lstok);
    if (err) {
	print_err("find lsass token", err);
	goto End;
    }

    if (!SetThreadToken(NULL, lstok)) {
	CloseHandle(lstok);
	err = GetLastError();
	print_err("Set lsass token", err);
	goto End;
    }
    CloseHandle(lstok);

    Status = CreateToken(htok,
			 TOKEN_ALL_ACCESS,
			 &oa,
			 TokenPrimary,
			 &session_id,
			 &tstats.ExpirationTime,
			 user, groups, privileges, &owner,
			 primary_group,
			 default_dacl, &TokenSource);

    RevertToSelf();

    if (Status) {
	print_err("CreateToken", LsaNtStatusToWinError(Status));
	goto End;
    }

 End:
    return err;
}
#endif

static void
usage(void)
{
    fprintf(stderr, "\ns4u.exe [options] [Domain\\]Username\n\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  --lsa - Use LsaLogonUser\n");
    fprintf(stderr, "  --s4u - Do an S4U login with --lsa\n");
    fprintf(stderr, "  --priv - Do not drop privileges\n");
    fprintf(stderr, "  --lsid - Fetch a logon sid and use it with --lsa\n");
    fprintf(stderr, "  --puser - Print the caller's token and quit\n");
    fprintf(stderr, "  --esids - Add some extra interactive sids\n");
    fprintf(stderr, "  --pw <str> - Use the given password\n");
}

int
_tmain (int argc, TCHAR *argv[])
{
    int exitCode = EXIT_FAILURE;
    NTSTATUS Status;
    NTSTATUS SubStatus;

    HANDLE hLsa = NULL;
    HANDLE hToken = NULL;
    HANDLE logon_tok = NULL;
    HANDLE tmph;

    OSVERSIONINFO osvi;
    BOOL bIsLocal = TRUE;

    LSA_STRING Msv1_0Name = { 0 };
    LSA_STRING OriginName = { 0 };
    void *auth_info = NULL;
    DWORD auth_info_len;
    LPTSTR password = NULL;
    MSV1_0_SET_OPTION SetOption;
    TOKEN_SOURCE TokenSource;
    ULONG ulAuthenticationPackage;
    SECURITY_LOGON_TYPE logon_type;

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
    LPTSTR szSrcCommandLine = TEXT("%systemroot%\\system32\\cmd.exe");
    LPTSTR szDomain = NULL;
    LPTSTR domain2 = NULL;
    LPTSTR szUsername = NULL;
    TCHAR seps[] = TEXT("\\");
    TCHAR *next_token = NULL;
    LPCWSTR userProfileDirectory = TEXT("C:\\");
    PMSV1_0_INTERACTIVE_PROFILE pInteractiveProfile = NULL;
    int arg;
    int err;
    size_t len;
    bool use_lsa = false;
    bool use_s4u = false;
    bool add_logon_sid = false;
    bool print_usertok = false;
    bool add_extra_sids = false;
    bool do_privileged = false;

    //
    // Ignore CTRL+C/CTRL+BREAK so we can wait for cmd.exe to handle it
    // and exit.
    //
    SetConsoleCtrlHandler(ConsoleControlHandler, TRUE);

    for (arg = 1; arg < argc; arg++) {
	if (argv[arg][0] != TEXT('-'))
	    break;
	if (_tcscmp(argv[arg], TEXT("--lsa")) == 0) {
	    use_lsa = true;
	} else if (_tcscmp(argv[arg], TEXT("--")) == 0) {
	    break;
	} else if (_tcscmp(argv[arg], TEXT("--s4u")) == 0) {
	    use_s4u = true;
	} else if (_tcscmp(argv[arg], TEXT("--priv")) == 0) {
	    do_privileged = true;
	} else if (_tcscmp(argv[arg], TEXT("--lsid")) == 0) {
	    add_logon_sid = true;
	} else if (_tcscmp(argv[arg], TEXT("--puser")) == 0) {
	    print_usertok = true;
	} else if (_tcscmp(argv[arg], TEXT("--esids")) == 0) {
	    add_extra_sids = true;
	} else if (_tcscmp(argv[arg], TEXT("--pw")) == 0) {
	    arg++;
	    if (arg >= argc) {
		fprintf(stderr, "No password supplied with --pw");
		goto End;
	    }
	    password = argv[arg];
	} else {
	    fprintf(stderr, "Unknown option: %ls\n", argv[arg]);
	    usage();
	    goto End;
	}
    }

    if (print_usertok) {
	printf("**** Calling user token:\n");
	print_tokinfo(NULL);
	goto End;
    }

    if (arg >= argc) {
	fprintf(stderr, "No user argument given\n");
	usage();
	goto End;
    }

    //
    // Get DOMAIN and USERNAME from command line.
    //
    if (_tcschr(argv[arg], TEXT('\\'))) {
	szDomain = _tcstok_s(argv[arg], seps, &next_token);
	domain2 = szDomain;
	szUsername = _tcstok_s(NULL, seps, &next_token);
    } else {
	szDomain = TEXT("");
	domain2 = NULL;
	szUsername = argv[arg];
	bIsLocal = TRUE;
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
    if (!GetVersionEx(&osvi)) {
	print_err("GetVersionEx", GetLastError());
	goto End;
    }

    OpenProcessToken(GetCurrentProcess(),
		     TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		     &hToken);
    err = set_privileges(hToken);
    if (err)
	goto End;

    //
    // Get logon SID
    //
    if (add_logon_sid) {
	err = get_logon_sid(hToken, &logon_sid);
	if (err){
	    print_err("Unable to get logon SID", err);
	    goto End;
	} else if (logon_sid) {
	    print_sid("logon_sid", logon_sid);
	} else {
	    printf("Logon SID not present\n");
	}
    }

    LSA_STRING name;
    LSA_OPERATIONAL_MODE dummy1;

    if (use_lsa) {
	/* Use LsaLogonUser. */

	/* Interactive, get a token we can use for that. */
	InitLsaString(&name, "S4U");
	Status = LsaRegisterLogonProcess(&name, &hLsa, &dummy1);
	if (Status != STATUS_SUCCESS) {
	    print_err("LsaRegisterLogonProcess",
		      LsaNtStatusToWinError(Status));
	    goto End;
	}

	//
	// Lookup for the MSV1_0 authentication package (NTLMSSP)
	//
	InitLsaString(&Msv1_0Name, MSV1_0_PACKAGE_NAME);
	Status = LsaLookupAuthenticationPackage(hLsa, &Msv1_0Name,
						&ulAuthenticationPackage);
	if (Status != STATUS_SUCCESS) {
	    print_err("LsaLookupAuthenticationPackage",
		      LsaNtStatusToWinError(Status));
	    goto End;
	}

	//
	// If account is not local to your system, we must set an
	// option to allow domain account. However, the account must be
	// in the domain accounts logon cache.  This option appears
	// with Windows 8/Server 2012.
	//
	if ((!bIsLocal) &&
	    ((osvi.dwMajorVersion > 6) || ((osvi.dwMajorVersion == 6) &&
					   (osvi.dwMinorVersion > 2)))) {
	    NTSTATUS ProtocolStatus;
	    PVOID pvReturnBuffer = NULL;
	    ULONG ulReturnBufferLength;

	    //
	    // Create MSV_1_0_SET_OPTION structure
	    //
	    memset(&SetOption, 0, sizeof(SetOption));
	    SetOption.MessageType = MsV1_0SetProcessOption;
	    SetOption.dwFlag = 0x20;

	    auth_info_len = sizeof(SetOption);

	    //
	    // Call LSA LsaCallAuthenticationPackage
	    //
	    Status = LsaCallAuthenticationPackage(hLsa,
						  ulAuthenticationPackage,
						  &SetOption,
						  auth_info_len,
						  &pvReturnBuffer,
						  &ulReturnBufferLength,
						  &ProtocolStatus);
	    if (Status != STATUS_SUCCESS) {
		print_err("LsaCallAuthenticationPackage",
			  LsaNtStatusToWinError(Status));
		goto End;
	    }
	}

	if (use_s4u) {
	    PMSV1_0_S4U_LOGON pS4uLogon;

	    //
	    // Create MSV1_0_S4U_LOGON structure
	    //
	    auth_info_len = (sizeof(MSV1_0_S4U_LOGON) +
			     ((wcslen(szDomain) + 1 +
			       wcslen(szUsername) + 1) * sizeof(WCHAR)));
	    pS4uLogon = (PMSV1_0_S4U_LOGON)malloc(auth_info_len);
	    if (pS4uLogon == NULL) {
		print_err("malloc", GetLastError());
		goto End;
	    }

	    pS4uLogon->MessageType = MsV1_0S4ULogon;
	    pbPosition = (PBYTE)pS4uLogon + sizeof(MSV1_0_S4U_LOGON);
	    pbPosition = InitUnicodeString(&pS4uLogon->UserPrincipalName,
					   szUsername, pbPosition);
	    pbPosition = InitUnicodeString(&pS4uLogon->DomainName, szDomain,
					   pbPosition);
	    auth_info = (void *) pS4uLogon;
	    logon_type = Network;
	} else {
	    MSV1_0_INTERACTIVE_LOGON *mi_logon;

	    if (!password) {
		fprintf(stderr,
			"You must use a password unless using lsa s4u\n");
		goto End;
	    }

	    auth_info_len = (sizeof(*mi_logon) +
			     ((wcslen(szDomain) + 1 +
			       wcslen(szUsername) + 1 +
			       wcslen(password) + 1) * sizeof(WCHAR)));
	    mi_logon = (MSV1_0_INTERACTIVE_LOGON *) malloc(auth_info_len);
	    if (!mi_logon) {
		print_err("malloc", GetLastError());
		goto End;
	    }
	    mi_logon->MessageType = MsV1_0InteractiveLogon;
	    pbPosition = ((PBYTE) mi_logon) + sizeof(*mi_logon);
	    pbPosition = InitUnicodeString(&mi_logon->LogonDomainName,
					   szDomain, pbPosition);
	    pbPosition = InitUnicodeString(&mi_logon->UserName,
					   szUsername, pbPosition);
	    pbPosition = InitUnicodeString(&mi_logon->Password,
					   password, pbPosition);
	    auth_info = (void *) mi_logon;
	    logon_type = Interactive;
	}

	//
	// Misc
	//
	strcpy_s(TokenSource.SourceName, TOKEN_SOURCE_LENGTH, "S4UWin");
	InitLsaString(&OriginName, "S4U for Windows");
	AllocateLocallyUniqueId(&TokenSource.SourceIdentifier);

	if (add_extra_sids || logon_sid) {
	    //
	    // Add extra SID to token.
	    //
	    // If the application needs to connect to a Windows Desktop,
	    // Logon SID must be added to the Token.
	    //
	    // Don't do this if we are not adding any SIDS, just pass
	    // in NULL.
	    //
	    len = sizeof(TOKEN_GROUPS) + ((1 + add_groups_len) *
					  sizeof(SID_AND_ATTRIBUTES));
	    extra_groups = (TOKEN_GROUPS *) malloc(len);
	    if (!extra_groups) {
		fprintf(stderr, "Allocate extra groups failed.\n");
		goto End;
	    }
	    memset(extra_groups, 0, len);
	}

	//
	// Add Logon Sid, if present.
	//
	if (logon_sid)
	    append_group(extra_groups, logon_sid, NULL,
			 (SE_GROUP_ENABLED | SE_GROUP_ENABLED_BY_DEFAULT |
			  SE_GROUP_MANDATORY));

	//
	// Add other groups from a list.
	//
	if (add_extra_sids) {
	    size_t i;

	    for (i = 0; i < add_groups_len; i++) {
		err = append_group(extra_groups, NULL, add_groups[i].name,
				   (SE_GROUP_ENABLED |
				    SE_GROUP_ENABLED_BY_DEFAULT |
				    SE_GROUP_MANDATORY));
		if (err) {
		    print_err("Unable to internal user-supplied group", err);
		    goto End;
		}
	    }
	}

	//
	// Call LSA LsaLogonUser
	//
	// This call required SeTcbPrivilege privilege:
	//    - [1] to get a primary token (vs impersonation token).
	//	The privilege MUST be activated.
	//    - [2] to add supplemental SID with LocalGroups parameter.
	//    - [3] to use a username with a domain name different from
	//	machine name (or '.').
	//
	Status = LsaLogonUser(hLsa,
			      &OriginName,
			      logon_type,
			      ulAuthenticationPackage,
			      auth_info,
			      auth_info_len,
			      extra_groups,
			      &TokenSource,
			      &pvProfile,
			      &dwProfile,
			      &logonId,
			      &logon_tok,
			      &quotaLimits,
			      &SubStatus);
	if (Status != STATUS_SUCCESS) {
	    print_err("LsaLogonUser", LsaNtStatusToWinError(Status));
	    goto End;
	}

#if 0
	//
	// Use NtCreateToken() to create a new token based upon the
	// LsaLogonUser token.
	//
	HANDLE htok;
	err = create_token_from_existing_token(logon_tok, &htok);
	if (err)
	    goto End;
	printf("***NTCreateToken:\n");
	pr_token_info(htok);
	CloseHandle(htok);
#endif

    } else {
	if (!password) {
	    fprintf(stderr,
		    "You must use a password unless using lsa s4u\n");
	    goto End;
	}

	if (!LogonUserEx(szUsername, domain2, password,
			 LOGON32_LOGON_INTERACTIVE,
			 LOGON32_PROVIDER_DEFAULT, &logon_tok,
			 NULL, &pvProfile, &dwProfile, &quotaLimits)) {
	    print_err("LogonUser", GetLastError());
	    goto End;
	}
	logon_type = Interactive;
    }

    if (logon_type != Network) {
	if (!DuplicateTokenEx(logon_tok, TOKEN_ALL_ACCESS,
			      NULL, SecurityImpersonation,
			      TokenImpersonation, &tmph)) {
	    print_err("Duplicate Token", GetLastError());
	    goto End;
	}
	CloseHandle(logon_tok);
	logon_tok = tmph;
    }

    //
    // Load the user profile.
    //
    pInteractiveProfile = (PMSV1_0_INTERACTIVE_PROFILE)pvProfile;
    if (pInteractiveProfile->MessageType == MsV1_0InteractiveProfile)
	profileInfo.lpServerName = pInteractiveProfile->LogonServer.Buffer;
    profileInfo.dwSize = sizeof(profileInfo);
    profileInfo.dwFlags = PI_NOUI;
    profileInfo.lpUserName = szUsername;
    if (!LoadUserProfile(logon_tok, &profileInfo)) {
	print_err("LoadUserProfile", GetLastError());
	goto End;
    }

    //
    // Load the user environment variables.
    //
    if (!CreateEnvironmentBlock(&lpUserEnvironment, logon_tok, FALSE)) {
	print_err("CreateEnvironmentBlock", GetLastError());
	goto End;
    }

    if (!do_privileged && logon_type == Network) {
	err = setup_process_token(&logon_tok, false);
	if (err) {
	    print_err("setup_process_token", err);
	    goto End;
	}
    }

    si.cb = sizeof(STARTUPINFO);
    si.lpDesktop = TEXT("winsta0\\default");

    //
    // Warning: szCommandLine parameter of CreateProcessAsUser() must
    // be writable
    //
    szCommandLine = (LPTSTR) malloc(MAX_PATH * sizeof(TCHAR));
    if (szCommandLine == NULL) {
	fprintf(stderr, "HeapAlloc failed (error %ld).\n", GetLastError());
	goto End;
    }

    if (!ExpandEnvironmentStrings(szSrcCommandLine, szCommandLine, MAX_PATH)) {
	print_err("ExpandEnvironmentStrings", GetLastError());
	goto End;
    }

    //
    // Get the User Profile directory.
    //
    // NB we could also have used the GetUserProfileDirectory function; but
    //    this way we do not have to deal with memory allocation.
    //
    for (LPCWSTR env = (LPCWSTR)lpUserEnvironment; *env;
		 env += wcslen(env) + 1) {
	if (!(wcsncmp(env, L"USERPROFILE=", wcslen(L"USERPROFILE=")))) {
	    userProfileDirectory = env + wcslen(L"USERPROFILE=");
	    break;
	}
    }

    
    if (!SetThreadToken(NULL, logon_tok)) {
	print_err("Set Thread token", GetLastError());
	goto End;
    }
	
    SECURITY_ATTRIBUTES secattr;
    memset(&secattr, 0, sizeof(secattr));
    secattr.nLength = sizeof(secattr);
    secattr.bInheritHandle = TRUE;
    if (!DuplicateTokenEx(logon_tok, 0,
			  &secattr, SecurityImpersonation, TokenPrimary, &tmph)) {
	print_err("Duplicate token", GetLastError());
	goto End;
    }
    CloseHandle(logon_tok);
    logon_tok = tmph;

#if 1
    //
    // CreateProcessAsUser requires these privileges to be available in
    // the current process:
    //
    //   SeTcbPrivilege (must be Enabled)
    //   SeAssignPrimaryTokenPrivilege (can be Disabled, will be
    //		automatically Enabled)
    //   SeIncreaseQuotaPrivilege (can be Disabled, will be automatically
    //		Enabled)
    //
    if (!CreateProcessAsUser(logon_tok,
			     NULL,
			     szCommandLine,
			     NULL,
			     NULL,
			     FALSE,
			     (NORMAL_PRIORITY_CLASS |
			      CREATE_UNICODE_ENVIRONMENT),
			     lpUserEnvironment,
			     userProfileDirectory,
			     &si,
			     &pi)) {
	print_err("CreateProcessAsUser", GetLastError());
	goto End;
    }
    RevertToSelf();
#else
    HANDLE lstok;
    err = find_lsass_tok(&lstok);
    if (err) {
	print_err("find lsass token", err);
	goto End;
    }

    err = set_privileges(lstok);
    if (err)
	goto End;

    if (!SetThreadToken(NULL, lstok)) {
	CloseHandle(lstok);
	err = GetLastError();
	print_err("Set lsass token", err);
	goto End;
    }
    CloseHandle(lstok);

    if (!CreateProcessWithTokenW(logon_tok,
				 0,
				 NULL,
				 szCommandLine,
				 (NORMAL_PRIORITY_CLASS |
				  CREATE_UNICODE_ENVIRONMENT),
				 lpUserEnvironment,
				 userProfileDirectory,
				 &si,
				 &pi)) {
	RevertToSelf();
	print_err("CreateProcessAsUser", GetLastError());
	goto End;
    }
    RevertToSelf();
#endif

    exitCode = EXIT_SUCCESS;

 End:
    if (Msv1_0Name.Buffer)
	free(Msv1_0Name.Buffer);
    if (OriginName.Buffer)
	free(OriginName.Buffer);
    if (logon_sid)
	free(logon_sid);
    if (pExtraSid)
	LocalFree(pExtraSid);
    if (auth_info)
	free(auth_info);
    if (extra_groups)
	free(extra_groups);
    if (pvProfile)
	LsaFreeReturnBuffer(pvProfile);
    if (hLsa)
	LsaClose(hLsa);
    if (lpUserEnvironment)
	DestroyEnvironmentBlock(lpUserEnvironment);
    if (profileInfo.hProfile)
	UnloadUserProfile(logon_tok, profileInfo.hProfile);
    if (hToken)
	CloseHandle(hToken);
    if (logon_tok)
	CloseHandle(logon_tok);
    if (pi.hThread)
	CloseHandle(pi.hThread);
    if (pi.hProcess) {
	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
    }

    return exitCode;
}
