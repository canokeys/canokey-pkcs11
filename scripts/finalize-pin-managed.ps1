[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$DllPath = (Join-Path $PSScriptRoot '..\build-ninja-clangcl-x64\canokey-pkcs11.dll'),
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

namespace CanokeyPkcs11 {
    public static class PinManagedProvisioning {
        private const uint CKR_OK = 0;
        private const uint CKF_RW_SESSION = 0x2;
        private const uint CKF_SERIAL_SESSION = 0x4;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CInitialize(IntPtr initArgs);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CFinalize(IntPtr reserved);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate uint CGetSlotList(byte tokenPresent, IntPtr slotList, ref uint count);

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

        public static void Run(string libraryPath, byte[] pin) {
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
                    uint slot = unchecked((uint)Marshal.ReadInt32(slots));
                    Check(openSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, IntPtr.Zero, IntPtr.Zero, out session),
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
if (-not $PSCmdlet.ShouldProcess('the attached CanoKey PIV application', 'Permanently block the PUK')) {
    return
}
if ($null -eq $Pin) {
    $Pin = Read-Host 'PIV PIN' -AsSecureString
}
$plainPin = [Net.NetworkCredential]::new('', $Pin).Password
$pinBytes = [Text.Encoding]::ASCII.GetBytes($plainPin)
try {
    Write-Host "Finalizing PIN-managed provisioning through $resolvedDll"
    Write-Host 'The PIV PUK will be permanently blocked.'
    [CanokeyPkcs11.PinManagedProvisioning]::Run($resolvedDll, $pinBytes)
    Write-Host 'PIN-managed provisioning finalized; PUK retries are zero.'
} finally {
    [Array]::Clear($pinBytes, 0, $pinBytes.Length)
    $plainPin = $null
}
