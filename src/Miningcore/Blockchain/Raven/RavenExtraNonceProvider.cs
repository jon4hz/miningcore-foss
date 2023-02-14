namespace Miningcore.Blockchain.Raven;

public class RavenExtraNonceProvider : ExtraNonceProviderBase
{
    public RavenExtraNonceProvider(string poolId, byte? clusterInstanceId) : base(poolId, RavenConstants.ExtranoncePlaceHolderLength, clusterInstanceId)
    {
    }
}
