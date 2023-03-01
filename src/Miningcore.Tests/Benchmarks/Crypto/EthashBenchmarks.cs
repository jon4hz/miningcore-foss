using Miningcore.Extensions;
using System.Globalization;
using System.Threading;
using System.Threading.Tasks;
using BenchmarkDotNet.Attributes;
using Miningcore.Crypto.Hashing.Ethash;
using NLog;

namespace Miningcore.Tests.Benchmarks.Crypto;


[MemoryDiagnoser]
public class EthashBenchmarks : TestBase
{
    private readonly byte[] testHash = "5fc898f16035bf5ac9c6d9077ae1e3d5fc1ecc3c9fd5bee8bb00e810fdacbaa0".HexToByteArray();
    private readonly ulong testNonce = ulong.Parse("50377003e5d830ca", NumberStyles.HexNumber, CultureInfo.InvariantCulture);
    private const int testHeight = 60000;

    private ILogger logger;

    private readonly EthashFull ethash = new EthashFull(3, Dag.GetDefaultDagDirectory());

    [GlobalSetup]
    public void Setup()
    {
        ModuleInitializer.Initialize();
        logger = new NullLogger(LogManager.LogFactory);

        // make sure to pre-load the DAG. This will take a while.
        ethash.GetDagAsync(testHeight, logger, CancellationToken.None).Wait();
    }


    [Benchmark]
    public async Task Ethash_Compute()
    {
        var cache = await ethash.GetDagAsync(testHeight,logger, CancellationToken.None);
        cache.Compute(logger, testHash, testNonce, out var mixDigest, out var result);
    }
}
