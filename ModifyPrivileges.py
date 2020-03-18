# author: size_t

# importing the required module to handle Windows API Calls
import ctypes

# importing Python -> Windows Types from ctypes
from ctypes.wintypes import DWORD

# Grab a handle to kernel32.dll & USer32.dll & Advapi32.dll
k_handle = ctypes.WinDLL("Kernel32.dll")
u_handle = ctypes.WinDLL("User32.dll")
a_handle = ctypes.WinDLL("Advapi32.dll")


# Access Rights
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0xFFF)

# Token Access Rights
STANDARD_RIGHTS_REQUIRED = 0x000F0000
STANDARD_RIGHTS_READ = 0x00020000
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_DUPLICATE = 0x0002
TOKEN_IMPERSONATION = 0x0004
TOKEN_QUERY = 0x0008
TOKEN_QUERY_SOURCE = 0x0010
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_ADJUST_GROUPS = 0x0040
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100
TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY)
TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | 
					TOKEN_ASSIGN_PRIMARY     |
					TOKEN_DUPLICATE          |
					TOKEN_IMPERSONATION      |
					TOKEN_QUERY              |
					TOKEN_QUERY_SOURCE       |
					TOKEN_ADJUST_PRIVILEGES  |
					TOKEN_ADJUST_GROUPS      |
					TOKEN_ADJUST_DEFAULT     |
					TOKEN_ADJUST_SESSIONID)


# privilege Enabled/Disabled mask
SE_PRIVILEGE_ENABLED = 0x00000002
SE_PRIVILEGE_DISABLED = 0x00000000

# needed structures for used API Calls
class LUID(ctypes.Structure):
	_fields_ = [
	("LowPart", DWORD),
	("HighPart", DWORD),
	]
	
class LUID_AND_ATTRIBUTES(ctypes.Structure):
	_fields_ = [
	("Luid", LUID),
	("Attributes", DWORD),
	]
	
class PRIVILEGE_SET(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount", DWORD),
	("Control", DWORD),
	("Privileges", LUID_AND_ATTRIBUTES),
	]

class TOKEN_PRIVILEGES(ctypes.Structure):
	_fields_ = [
	("PrivilegeCount", DWORD),
	("Privileges", LUID_AND_ATTRIBUTES),
	]


# getting the Windows Name from User32
lpWindowName = ctypes.c_char_p(input("Enter Window Name To Hook Into: ").encode('utf-8'))

# getting a handle to the process
hWnd = u_handle.FindWindowA(None, lpWindowName)

# checking to see if we have the handle
if hWnd == 0:
	print("[ERROR] Could Not Grab Handle! Error Code: {0}".format(k_handle.GetLastError()))
	exit(1)
else:
	print("[INFO] Grabbed Handle...")
	
# getting the PID of the process at the handle
lpdwProcessId = ctypes.c_ulong()

# we use byref to pass a pointer to the value as needed by the API Call
response = u_handle.GetWindowThreadProcessId(hWnd, ctypes.byref(lpdwProcessId))

# checking to see if the call completed
if response == 0:
	print("[ERROR] Could Not Get PID from Handle! Error Code: {0}".format(k_handle.GetLastError()))
else:
	print("[INFO] Found PID...")
	

# opening the process by PID with specific access
dwDesiredAccess = PROCESS_ALL_ACCESS
bInheritHandle = False
dwProcessId = lpdwProcessId

# calling the Windows API Call to open the process
hProcess = k_handle.OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId)

# checking to see if we have a valid Handle to the process
if hProcess <= 0:
	print("[ERROR] Could Not Grab Privileged Handle! Error Code: {0}".format(k_handle.GetLastError()))
else:
	print("[INFO] Privileged Handle Opened...")
	
# opening a handle to the process's token directly
ProcessHandle = hProcess
DesiredAccess = TOKEN_ALL_ACCESS
TokenHandle = ctypes.c_void_p()

# issuing the API Call
response = k_handle.OpenProcessToken(ProcessHandle, DesiredAccess, ctypes.byref(TokenHandle))

# handling any errors
if response > 0:
	print("[INFO] Handle to Process Token Created! Token: {0}".format(TokenHandle))
else:
	print("[ERROR] Could Not Grab Privileged Handle to Token! Error Code: {0}".format(k_handle.GetLastError()))

# checking to see if we have SEDebugPrivilege
# first use the LookupPrivilegeValue API Call to get the LUID based on the string privilege name

# setting up a PRIVILEGE_SET for the PrivilegeCheck call to be used later - We need the LUID to be used
# we will reference it later as well
requiredPrivileges = PRIVILEGE_SET()
requiredPrivileges.PrivilegeCount = 1 # We are only looking at 1 Privilege at a time here
requiredPrivileges.Privileges = LUID_AND_ATTRIBUTES() # Setup a new LUID_AND_ATTRIBUTES
requiredPrivileges.Privileges.Luid = LUID() # Setup a New LUID inside of the LUID_AND_ATTRIBUTES structure

# parameters for lookup API Call
lpSystemName = None
lpName = "SEDebugPrivilege"

# we now issue the call to configure the LUID with the systems value of that privilege
response = a_handle.LookupPrivilegeValueW(lpSystemName, lpName, ctypes.byref(requiredPrivileges.Privileges.Luid))

# handling any errors
if response > 0:
	print("[INFO] Lookup For SEDebugPrivilege Worked...")
else:
	print("[ERROR] Lookup for SEDebugPrivilege Failed! Error Code: {0}".format(k_handle.GetLastError()))

# now that our LUID is setup and pointing to the correct privilege we can check to see if its enabled
pfResult = ctypes.c_long()

response = a_handle.PrivilegeCheck(TokenHandle, ctypes.byref(requiredPrivileges), ctypes.byref(pfResult))

# handling any errors
if response > 0:
	print("[INFO] PrivilegeCheck Worked...")
else:
	print("[ERROR] PrivilegeCheck Failed! Error Code: {0}".format(k_handle.GetLastError()))

# we can check pfResult to see if our privilege is enabled or not
if pfResult:
	print("[INFO] Privilege SEDebugPrivilege is Enabled...")
	requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_DISABLED # disable if its currently enabled
else:
	print("[INFO] Privilege SEDebugPrivilege is NOT Enabled...")
	requiredPrivileges.Privileges.Attributes = SE_PRIVILEGE_ENABLED # enable if currently disabled

# we will not attempt to modify the selected privilege in the Token
DisableAllPrivileges = False
NewState = TOKEN_PRIVILEGES()
BufferLength = ctypes.sizeof(NewState)
PreviousState = ctypes.c_void_p()
ReturnLength = ctypes.c_void_p()

# configure token privileges
NewState.PrivilegeCount = 1;
NewState.Privileges = requiredPrivileges.Privileges # set the LUID_AND_ATTRIBUTES to our new structure

response = a_handle.AdjustTokenPrivileges(
	TokenHandle, 
	DisableAllPrivileges, 
	ctypes.byref(NewState), 
	BufferLength, 
	ctypes.byref(PreviousState),
	ctypes.byref(ReturnLength))
	
# handling any errors
if response > 0:
	print("[INFO] AdjustTokenPrivileges Flipped Privilege...")
else:
	print("[ERROR] AdjustTokenPrivileges Failed! Error Code: {0}".format(k_handle.GetLastError()))
