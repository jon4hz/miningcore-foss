using System.Runtime.InteropServices;

// ReSharper disable FieldCanBeMadeReadOnly.Local
// ReSharper disable MemberCanBePrivate.Local
// ReSharper disable InconsistentNaming

namespace Miningcore.Native;

public static unsafe class KawPow
{
    [DllImport("libkawpow", EntryPoint = "ethash_create_epoch_context", CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr CreateContext(int epoch_number);

    [DllImport("libkawpow", EntryPoint = "ethash_destroy_epoch_context", CallingConvention = CallingConvention.Cdecl)]
    private static extern void DestroyContext(IntPtr context);

    [DllImport("libkawpow", EntryPoint = "hash", CallingConvention = CallingConvention.Cdecl)]
    private static extern Ethash_result hash(IntPtr context, int block_number, ref Ethash_hash256 header_hash, ulong nonce, ref Ethash_hash256 mix_hash);

    [DllImport("libkawpow", EntryPoint = "ethash_calculate_epoch_seed", CallingConvention = CallingConvention.Cdecl)]
    private static extern Ethash_hash256 calculate_epoch_seed(int epoch_number);

    [StructLayout(LayoutKind.Explicit)]
    private struct Ethash_hash256
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
        public byte[] bytes;//x32
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Ethash_result
    {
        public Ethash_hash256 final_hash;//32
        public Ethash_hash256 mix_hash;//32
    }
}
