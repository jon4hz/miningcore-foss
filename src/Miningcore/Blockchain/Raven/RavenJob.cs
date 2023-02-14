using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Miningcore.Blockchain.Bitcoin.Configuration;
using Miningcore.Blockchain.Bitcoin.DaemonResponses;
using Miningcore.Configuration;
using Miningcore.Crypto;
using Miningcore.Crypto.Hashing.Kawpow;
using Miningcore.Extensions;
using Miningcore.Stratum;
using Miningcore.Time;
using Miningcore.Util;
using NBitcoin;
using NBitcoin.DataEncoders;
using NLog;
using Contract = Miningcore.Contracts.Contract;
using Transaction = NBitcoin.Transaction;

namespace Miningcore.Blockchain.Raven;

public class RavenJobParams
{
    public ulong Height { get; set; }
    public bool CleanJobs { get; set; }
}

public class RavenJob
{
    protected IMasterClock clock;
    protected double shareMultiplier;
    protected IHashAlgorithm coinbaseHasher;
    protected IHashAlgorithm headerHasher;
    protected Cache kawpowHasher;

    protected Network network;
    protected IDestination poolAddressDestination;
    protected RavenTemplate coin;
    protected readonly ConcurrentDictionary<string, bool> submissions = new(StringComparer.OrdinalIgnoreCase);
    protected uint256 blockTargetValue;
    protected byte[] coinbaseFinal;
    protected string coinbaseFinalHex;
    protected byte[] coinbaseInitial;
    protected string coinbaseInitialHex;
    protected string[] merkleBranchesHex;
    protected MerkleTree mt;

    ///////////////////////////////////////////
    // GetJobParams related properties

    protected RavenJobParams jobParams;
    protected Money rewardToPool;
    protected Transaction txOut;

    // serialization constants
    protected byte[] scriptSigFinalBytes;

    protected static byte[] sha256Empty = new byte[32];
    protected uint txVersion = 1u; // transaction version (currently 1) - see https://en.bitcoin.it/wiki/Transaction

    protected static uint txInputCount = 1u;
    protected static uint txInPrevOutIndex = (uint) (Math.Pow(2, 32) - 1);
    protected static uint txInSequence;
    protected static uint txLockTime;

    protected virtual void BuildMerkleBranches()
    {
        var transactionHashes = BlockTemplate.Transactions
            .Select(tx => (tx.TxId ?? tx.Hash)
            //.Select(tx => (tx.TxId)
                .HexToByteArray()
                .ReverseInPlace())
            .ToArray();

        mt = new MerkleTree(transactionHashes);

        merkleBranchesHex = mt.Steps
            .Select(x => x.ToHexString())
            .ToArray();
    }

    protected virtual void BuildCoinbase()
    {
        // generate script parts
        var sigScriptInitial = GenerateScriptSigInitial();
        var sigScriptInitialBytes = sigScriptInitial.ToBytes();

        var sigScriptLength = (uint) (
            sigScriptInitial.Length +
            RavenConstants.ExtranoncePlaceHolderLength +
            scriptSigFinalBytes.Length);

        // output transaction
        txOut = CreateOutputTransaction();

        // build coinbase initial
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // version
            bs.ReadWrite(ref txVersion);

            // serialize (simulated) input transaction
            bs.ReadWriteAsVarInt(ref txInputCount);
            bs.ReadWrite(ref sha256Empty);
            bs.ReadWrite(ref txInPrevOutIndex);

            // signature script initial part
            bs.ReadWriteAsVarInt(ref sigScriptLength);
            bs.ReadWrite(ref sigScriptInitialBytes);

            // done
            coinbaseInitial = stream.ToArray();
            coinbaseInitialHex = coinbaseInitial.ToHexString();
        }

        // build coinbase final
        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // signature script final part
            bs.ReadWrite(ref scriptSigFinalBytes);

            // tx in sequence
            bs.ReadWrite(ref txInSequence);

            // serialize output transaction
            var txOutBytes = SerializeOutputTransaction(txOut);
            bs.ReadWrite(ref txOutBytes);

            // misc
            bs.ReadWrite(ref txLockTime);

            // done
            coinbaseFinal = stream.ToArray();
            coinbaseFinalHex = coinbaseFinal.ToHexString();
        }
    }

    protected virtual byte[] SerializeOutputTransaction(Transaction tx)
    {
        var withDefaultWitnessCommitment = !string.IsNullOrEmpty(BlockTemplate.DefaultWitnessCommitment);

        var outputCount = (uint) tx.Outputs.Count;
        if(withDefaultWitnessCommitment)
            outputCount++;

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            // write output count
            bs.ReadWriteAsVarInt(ref outputCount);

            long amount;
            byte[] raw;
            uint rawLength;

            // serialize outputs
            foreach(var output in tx.Outputs)
            {
                amount = output.Value.Satoshi;
                var outScript = output.ScriptPubKey;
                raw = outScript.ToBytes(true);
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            // serialize witness (segwit)
            if(withDefaultWitnessCommitment)
            {
                amount = 0;
                raw = BlockTemplate.DefaultWitnessCommitment.HexToByteArray();
                rawLength = (uint) raw.Length;

                bs.ReadWrite(ref amount);
                bs.ReadWriteAsVarInt(ref rawLength);
                bs.ReadWrite(ref raw);
            }

            return stream.ToArray();
        }
    }

    protected virtual Script GenerateScriptSigInitial()
    {
        var now = ((DateTimeOffset) clock.Now).ToUnixTimeSeconds();

        // script ops
        var ops = new List<Op>();

        // push block height
        ops.Add(Op.GetPushOp(BlockTemplate.Height));

        // optionally push aux-flags
        if(!coin.CoinbaseIgnoreAuxFlags && !string.IsNullOrEmpty(BlockTemplate.CoinbaseAux?.Flags))
            ops.Add(Op.GetPushOp(BlockTemplate.CoinbaseAux.Flags.HexToByteArray()));

        // push timestamp
        ops.Add(Op.GetPushOp(now));

        // push placeholder
        ops.Add(Op.GetPushOp(0));

        return new Script(ops);
    }

    protected virtual Transaction CreateOutputTransaction()
    {
        rewardToPool = new Money(BlockTemplate.CoinbaseValue, MoneyUnit.Satoshi);
        var tx = Transaction.Create(network);

        // Remaining amount goes to pool
        tx.Outputs.Add(rewardToPool, poolAddressDestination);

        return tx;
    }


    protected byte[] SerializeHeader(Span<byte> coinbaseHash)
    {
        // build merkle-root
        var merkleRoot = mt.WithFirst(coinbaseHash.ToArray());

        // Build version
        var version = BlockTemplate.Version;

#pragma warning disable 618
        var blockHeader = new BlockHeader
#pragma warning restore 618
        {
            Version = unchecked((int) version),
            Bits = new Target(Encoders.Hex.DecodeData(BlockTemplate.Bits)),
            HashPrevBlock = uint256.Parse(BlockTemplate.PreviousBlockhash),
            HashMerkleRoot = new uint256(merkleRoot),
            BlockTime = DateTimeOffset.FromUnixTimeSeconds(BlockTemplate.CurTime),
            Nonce = BlockTemplate.Height
        };

        return blockHeader.ToBytes();
    }

    protected virtual (Share Share, string BlockHex) ProcessShareInternal(ILogger logger,
        StratumConnection worker, ulong nonce, string inputHeaderHash, string mixHash)
    {
        var context = worker.ContextAs<RavenWorkerContext>();
        var extraNonce1 = context.ExtraNonce1;

        // build coinbase
        var coinbase = SerializeCoinbase(extraNonce1);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        // hash block-header
        var headerBytes = SerializeHeader(coinbaseHash);
        Span<byte> headerHash = stackalloc byte[32];
        headerHasher.Digest(headerBytes, headerHash);
        headerHash.Reverse();

        var headerValue = new uint256(headerHash);
        var headerHashHex = headerHash.ToHexString();

        if(headerHashHex != inputHeaderHash)
        {
            throw new StratumException(StratumError.MinusOne, "bad header-hash");
        }

        if(!kawpowHasher.Compute(logger, (int) BlockTemplate.Height, headerHash.ToArray(), nonce, out var mixHashOut, out var resultBytes))
            throw new StratumException(StratumError.MinusOne, "bad hash");

        resultBytes.ReverseInPlace();
        mixHashOut.ReverseInPlace();

        var resultValue = new uint256(resultBytes);
        var resultValueBig = resultBytes.AsSpan().ToBigInteger();
        // calc share-diff
        var shareDiff = (double) new BigRational(RavenConstants.Diff1, resultValueBig) * shareMultiplier;
        var stratumDifficulty = context.Difficulty;
        var ratio = shareDiff / stratumDifficulty;

        // check if the share meets the much harder block difficulty (block candidate)
        var isBlockCandidate = resultValue <= blockTargetValue;

        // test if share meets at least workers current difficulty
        if(!isBlockCandidate && ratio < 0.99)
        {
            // check if share matched the previous difficulty from before a vardiff retarget
            if(context.VarDiff?.LastUpdate != null && context.PreviousDifficulty.HasValue)
            {
                ratio = shareDiff / context.PreviousDifficulty.Value;

                if(ratio < 0.99)
                    throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");

                // use previous difficulty
                stratumDifficulty = context.PreviousDifficulty.Value;
            }

            else
                throw new StratumException(StratumError.LowDifficultyShare, $"low difficulty share ({shareDiff})");
        }

        var result = new Share
        {
            BlockHeight = BlockTemplate.Height,
            NetworkDifficulty = Difficulty,
            Difficulty = stratumDifficulty / shareMultiplier,
        };

        if(isBlockCandidate)
        {
            result.IsBlockCandidate = true;
            result.BlockHash = resultBytes.ReverseInPlace().ToHexString();

            var blockBytes = SerializeBlock(headerBytes, coinbase, nonce, mixHashOut);
            var blockHex = blockBytes.ToHexString();

            return (result, blockHex);
        }

        return (result, null);
    }

    protected virtual byte[] SerializeCoinbase(string extraNonce1)
    {
        var extraNonce1Bytes = extraNonce1.HexToByteArray();

        using(var stream = new MemoryStream())
        {
            stream.Write(coinbaseInitial);
            stream.Write(extraNonce1Bytes);
            stream.Write(coinbaseFinal);

            return stream.ToArray();
        }
    }

    protected virtual byte[] SerializeBlock(byte[] header, byte[] coinbase, ulong nonce, byte[] mixHash)
    {
        var rawTransactionBuffer = BuildRawTransactionBuffer();
        var transactionCount = (uint) BlockTemplate.Transactions.Length + 1; // +1 for prepended coinbase tx

        using(var stream = new MemoryStream())
        {
            var bs = new BitcoinStream(stream, true);

            bs.ReadWrite(ref header);
            bs.ReadWrite(ref nonce);
            bs.ReadWrite(ref mixHash);
            bs.ReadWriteAsVarInt(ref transactionCount);

            bs.ReadWrite(ref coinbase);
            bs.ReadWrite(ref rawTransactionBuffer);

            return stream.ToArray();
        }
    }

    protected virtual byte[] BuildRawTransactionBuffer()
    {
        using(var stream = new MemoryStream())
        {
            foreach(var tx in BlockTemplate.Transactions)
            {
                var txRaw = tx.Data.HexToByteArray();
                stream.Write(txRaw);
            }

            return stream.ToArray();
        }
    }

    #region API-Surface

    public BlockTemplate BlockTemplate { get; protected set; }
    public double Difficulty { get; protected set; }

    public string JobId { get; protected set; }

    public void Init(BlockTemplate blockTemplate, string jobId,
        PoolConfig pc, BitcoinPoolConfigExtra extraPoolConfig,
        ClusterConfig cc, IMasterClock clock,
        IDestination poolAddressDestination, Network network,
        bool isPoS, double shareMultiplier, IHashAlgorithm coinbaseHasher,
        IHashAlgorithm headerHasher, Cache kawpowHasher)
    {
        Contract.RequiresNonNull(blockTemplate);
        Contract.RequiresNonNull(pc);
        Contract.RequiresNonNull(cc);
        Contract.RequiresNonNull(clock);
        Contract.RequiresNonNull(poolAddressDestination);
        Contract.RequiresNonNull(coinbaseHasher);
        Contract.RequiresNonNull(headerHasher);
        Contract.RequiresNonNull(kawpowHasher);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(jobId));

        coin = pc.Template.As<RavenTemplate>();
        txVersion = coin.CoinbaseTxVersion;
        this.network = network;
        this.clock = clock;
        this.poolAddressDestination = poolAddressDestination;
        BlockTemplate = blockTemplate;
        JobId = jobId;

        var coinbaseString = !string.IsNullOrEmpty(cc.PaymentProcessing?.CoinbaseString) ?
            cc.PaymentProcessing?.CoinbaseString.Trim() : "Miningcore";

        scriptSigFinalBytes = new Script(Op.GetPushOp(Encoding.UTF8.GetBytes(coinbaseString))).ToBytes();

        Difficulty = new Target(System.Numerics.BigInteger.Parse(BlockTemplate.Target, NumberStyles.HexNumber)).Difficulty;

        this.shareMultiplier = shareMultiplier;

        this.coinbaseHasher = coinbaseHasher;
        this.headerHasher = headerHasher;
        this.kawpowHasher = kawpowHasher;

        if(!string.IsNullOrEmpty(BlockTemplate.Target))
            blockTargetValue = new uint256(BlockTemplate.Target);
        else
        {
            var tmp = new Target(BlockTemplate.Bits.HexToByteArray());
            blockTargetValue = tmp.ToUInt256();
        }

        BuildMerkleBranches();
        BuildCoinbase();

        jobParams = new RavenJobParams
        {
            Height = BlockTemplate.Height,
            CleanJobs = false
        };
    }

    public virtual void PrepareWorkerJob(ILogger logger, RavenWorkerJob workerJob, out string headerHash)
    {
        workerJob.Job = this;
        workerJob.Height = BlockTemplate.Height;
        workerJob.Bits = BlockTemplate.Bits;
        workerJob.SeedHash = kawpowHasher.SeedHash.ToHexString();
        headerHash = CreateHeaderHash(logger, workerJob);
    }

    protected virtual string CreateHeaderHash(ILogger logger, RavenWorkerJob workerJob)
    {
        var headerHasher = coin.HeaderHasherValue;
        var coinbaseHasher = coin.CoinbaseHasherValue;
        var extraNonce1 = workerJob.ExtraNonce1;

        var coinbase = SerializeCoinbase(workerJob.ExtraNonce1);
        Span<byte> coinbaseHash = stackalloc byte[32];
        coinbaseHasher.Digest(coinbase, coinbaseHash);

        var headerBytes = SerializeHeader(coinbaseHash);
        Span<byte> headerHash = stackalloc byte[32];
        headerHasher.Digest(headerBytes, headerHash);
        headerHash.Reverse();

        return headerHash.ToHexString();
    }

    public object GetJobParams(bool isNew)
    {
        jobParams.CleanJobs = isNew;
        return jobParams;
    }

    public virtual (Share Share, string BlockHex) ProcessShare(ILogger logger, StratumConnection worker, string nonce, string headerHash, string mixHash)
    {
        Contract.RequiresNonNull(worker);
        Contract.Requires<ArgumentException>(!string.IsNullOrEmpty(nonce));

        var context = worker.ContextAs<RavenWorkerContext>();

        // mixHash
        if(mixHash.Length != 64)
            throw new StratumException(StratumError.Other, $"incorrect size of mixHash: {mixHash}");

        // validate nonce
        if(nonce.Length != 16)
            throw new StratumException(StratumError.Other, $"incorrect size of nonce: {nonce}");

        // check if nonce is within range
        if(nonce.IndexOf(context.ExtraNonce1.Substring(0, 4)) != 0)
            throw new StratumException(StratumError.Other, $"nonce out of range: {nonce}");

        var nonceLong = ulong.Parse(nonce, NumberStyles.HexNumber);

        return ProcessShareInternal(logger, worker, nonceLong, headerHash, mixHash);
    }

    #endregion // API-Surface
}
