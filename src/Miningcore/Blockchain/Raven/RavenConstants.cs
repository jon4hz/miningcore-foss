using Org.BouncyCastle.Math;

namespace Miningcore.Blockchain.Raven;

public class RavenConstants
{
    public const int EpochLength = 7500;
    public static readonly BigInteger Diff1 = new BigInteger("00ff000000000000000000000000000000000000000000000000000000", 16);
    public const int TargetPaddingLength = 32;
}
