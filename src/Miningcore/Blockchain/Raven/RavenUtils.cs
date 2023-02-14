using Miningcore.Extensions;
using Org.BouncyCastle.Math;

namespace Miningcore.Blockchain.Raven;

public static class RavenUtils
{
    public static string EncodeTarget(double difficulty)
    {
        string result;
        var diff = BigInteger.ValueOf((long) (difficulty * 255d));
        var quotient = RavenConstants.Diff1B.Divide(diff).Multiply(BigInteger.ValueOf(255));
        var bytes = quotient.ToByteArray().AsSpan();
        Span<byte> padded = stackalloc byte[RavenConstants.TargetPaddingLength];

        var padLength = RavenConstants.TargetPaddingLength - bytes.Length;

        if(padLength > 0)
        {
            bytes.CopyTo(padded.Slice(padLength, bytes.Length));
            result = padded.ToHexString(0, RavenConstants.TargetPaddingLength);
        }

        else
            result = bytes.ToHexString(0, RavenConstants.TargetPaddingLength);

        return result;
    }
}