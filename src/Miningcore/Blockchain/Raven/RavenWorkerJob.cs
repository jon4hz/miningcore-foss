using System.Collections.Concurrent;

namespace Miningcore.Blockchain.Raven;

public class RavenWorkerJob
{
    public RavenWorkerJob(string jobId, string extraNonce1)
    {
        Id = jobId;
        ExtraNonce1 = extraNonce1;
    }

    public string Id { get; }
    public RavenJob Job { get; set; }
    public uint Height { get; set; }
    public string ExtraNonce1 { get; set; }
    public string Bits { get; set; }

    public readonly ConcurrentDictionary<string, bool> Submissions = new(StringComparer.OrdinalIgnoreCase);
}