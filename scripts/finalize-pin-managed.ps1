[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DllPath = (Join-Path $PSScriptRoot '..\build-ninja-clangcl-x64\canokey-pkcs11.dll'),
    [Parameter(Mandatory)]
    [uint32]$SlotId,
    [Parameter(Mandatory)]
    [string]$ExpectedSerial,
    [Security.SecureString]$Pin,
    [switch]$AcknowledgePermanentPukBlock
)

$ErrorActionPreference = 'Stop'

if (-not $AcknowledgePermanentPukBlock) {
    throw 'This operation permanently blocks the PIV PUK. Pass -AcknowledgePermanentPukBlock to continue.'
}
if (-not ('CanokeyPkcs11.PinManagedProvisioning' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace CanokeyPkcs11 {
    public static class PinManagedProvisioning {
        private const uint CKR_OK = 0;
        private const uint CKF_RW_SESSION = 0x2;
        private const uint CKF_SERIAL_SESSION = 0x4;

        [StructLayout(LayoutKind.Sequential)]
        private struct CK_VERSION {
            public byte major;
            public byte minor;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CK_TOKEN_INFO {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] label;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)] public byte[] manufacturerID;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] model;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] serialNumber;
            public uint flags;
            public uint maxSessionCount;
            public uint sessionCount;
            public uint maxRwSessionCount;
            public uint rwSessionCount;
            public uint maxPinLen;
            public uint minPinLen;
            public uint totalPublicMemory;
            public uint freePublicMemory;
            public uint totalPrivateMemory;
            public uint freePrivateMemory;
            public CK_VERSION hardwareVersion;
            public CK_VERSION firmwareVersion;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] utcTime;
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CInitialize(IntPtr initArgs);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CFinalize(IntPtr reserved);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CGetSlotList(byte tokenPresent, IntPtr slotList, ref uint count);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CGetTokenInfo(uint slotId, out CK_TOKEN_INFO info);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint COpenSession(uint slotId, uint flags, IntPtr application, IntPtr notify, out uint session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CCloseSession(uint session);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CFinalizePinManaged(uint session, byte[] pin, uint pinLength);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr LoadLibrary(string fileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr module, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FreeLibrary(IntPtr module);

        private static T LoadFunction<T>(IntPtr module, string name) where T : Delegate {
            IntPtr address = GetProcAddress(module, name);
            if (address == IntPtr.Zero) {
                throw new InvalidOperationException("Missing PKCS#11 export " + name);
            }
            return Marshal.GetDelegateForFunctionPointer<T>(address);
        }

        private static void Check(uint status, string operation) {
            if (status != CKR_OK) {
                throw new InvalidOperationException(operation + " failed with CK_RV 0x" + status.ToString("X8"));
            }
        }

        private static string DecodePadded(byte[] value) {
            return Encoding.ASCII.GetString(value).TrimEnd(' ', '\0');
        }

        public static void Run(string libraryPath, byte[] pin, uint expectedSlot, string expectedSerial) {
            IntPtr module = LoadLibrary(libraryPath);
            if (module == IntPtr.Zero) {
                throw new InvalidOperationException("LoadLibrary failed for " + libraryPath + ": " +
                    Marshal.GetLastWin32Error());
            }

            uint session = 0;
            bool initialized = false;
            try {
                CInitialize initialize = LoadFunction<CInitialize>(module, "C_Initialize");
                CFinalize finalize = LoadFunction<CFinalize>(module, "C_Finalize");
                CGetSlotList getSlotList = LoadFunction<CGetSlotList>(module, "C_GetSlotList");
                CGetTokenInfo getTokenInfo = LoadFunction<CGetTokenInfo>(module, "C_GetTokenInfo");
                COpenSession openSession = LoadFunction<COpenSession>(module, "C_OpenSession");
                CCloseSession closeSession = LoadFunction<CCloseSession>(module, "C_CloseSession");
                CFinalizePinManaged finalizePinManaged =
                    LoadFunction<CFinalizePinManaged>(module, "C_CNK_FinalizePinManaged");

                Check(initialize(IntPtr.Zero), "C_Initialize");
                initialized = true;

                uint count = 0;
                Check(getSlotList(1, IntPtr.Zero, ref count), "C_GetSlotList(size)");
                if (count == 0) {
                    throw new InvalidOperationException("No PKCS#11 token is present.");
                }

                IntPtr slots = Marshal.AllocHGlobal(checked((int)(count * sizeof(uint))));
                try {
                    Check(getSlotList(1, slots, ref count), "C_GetSlotList");
                    bool found = false;
                    CK_TOKEN_INFO selectedInfo = new CK_TOKEN_INFO();
                    for (uint i = 0; i < count; i++) {
                        uint candidate = unchecked((uint)Marshal.ReadInt32(slots, checked((int)(i * sizeof(uint)))));
                        if (candidate != expectedSlot) continue;
                        Check(getTokenInfo(candidate, out selectedInfo), "C_GetTokenInfo");
                        found = true;
                        break;
                    }
                    if (!found) {
                        throw new InvalidOperationException("Requested slot " + expectedSlot + " is not present.");
                    }
                    string actualSerial = DecodePadded(selectedInfo.serialNumber);
                    string label = DecodePadded(selectedInfo.label);
                    if (!String.Equals(actualSerial, expectedSerial, StringComparison.Ordinal)) {
                        throw new InvalidOperationException("Slot " + expectedSlot + " serial mismatch: expected " +
                            expectedSerial + ", found " + actualSerial + ".");
                    }
                    Console.WriteLine("Verified target slot " + expectedSlot + ", serial " + actualSerial +
                        ", token '" + label + "'.");
                    Check(openSession(expectedSlot, CKF_SERIAL_SESSION | CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, out session),
                        "C_OpenSession");
                    Check(finalizePinManaged(session, pin, checked((uint)pin.Length)),
                        "C_CNK_FinalizePinManaged");
                } finally {
                    Marshal.FreeHGlobal(slots);
                }

                Check(closeSession(session), "C_CloseSession");
                session = 0;
                Check(finalize(IntPtr.Zero), "C_Finalize");
                initialized = false;
            } finally {
                if (session != 0) {
                    try { LoadFunction<CCloseSession>(module, "C_CloseSession")(session); } catch { }
                }
                if (initialized) {
                    try { LoadFunction<CFinalize>(module, "C_Finalize")(IntPtr.Zero); } catch { }
                }
                FreeLibrary(module);
            }
        }
    }
}
'@
}

$resolvedDll = (Resolve-Path -LiteralPath $DllPath).ProviderPath
if (-not $PSCmdlet.ShouldProcess("CanoKey PKCS#11 slot $SlotId with serial $ExpectedSerial", 'Permanently block the PUK')) {
    return
}
if ($null -eq $Pin) {
    $Pin = Read-Host 'PIV PIN' -AsSecureString
}
$pinBstr = [IntPtr]::Zero
$pinBytes = $null
try {
    $pinBstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pin)
    $pinLength = [Runtime.InteropServices.Marshal]::ReadInt32($pinBstr, -4) / 2
    $pinBytes = [byte[]]::new($pinLength)
    for ($i = 0; $i -lt $pinLength; $i++) {
        $codePoint = [Runtime.InteropServices.Marshal]::ReadInt16($pinBstr, $i * 2)
        if ($codePoint -lt 0 -or $codePoint -gt 0x7f) {
            throw 'PIV PIN must contain ASCII characters only.'
        }
        $pinBytes[$i] = [byte]$codePoint
    }
    Write-Host "Finalizing PIN-managed provisioning through $resolvedDll"
    Write-Host "The PIV PUK on slot $SlotId, serial $ExpectedSerial, will be permanently blocked."
    [CanokeyPkcs11.PinManagedProvisioning]::Run($resolvedDll, $pinBytes, $SlotId, $ExpectedSerial)
    Write-Host 'PIN-managed provisioning finalized; PUK retries are zero.'
} finally {
    if ($null -ne $pinBytes) {
        [Array]::Clear($pinBytes, 0, $pinBytes.Length)
    }
    if ($pinBstr -ne [IntPtr]::Zero) {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pinBstr)
    }
}
