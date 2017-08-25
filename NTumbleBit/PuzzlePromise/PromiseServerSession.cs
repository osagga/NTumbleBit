using NBitcoin;
using NBitcoin.Crypto;
using NTumbleBit.ClassicTumbler;
using NTumbleBit.PuzzleSolver;
using System;
using System.Linq;

namespace NTumbleBit.PuzzlePromise
{
    public enum PromiseServerStates
    {
        WaitingEscrow,
        WaitingHashes,
        WaitingRevelation,
        Completed
    }

    public class PromiseServerSession : EscrowInitiator
    {
        public class EncryptedSignature
        {
            public EncryptedSignature()
            {

            }
            public EncryptedSignature(ECDSASignature ecdsa, uint256 signedHash, PuzzleSolution solution)
            {
                Signature = ecdsa;
                PuzzleSolution = solution;
                SignedHash = signedHash;
            }

            public uint256 SignedHash
            {
                get; set;
            }
            public ECDSASignature Signature
            {
                get; set;
            }

            public PuzzleSolution PuzzleSolution
            {
                get; set;
            }
        }
        public PromiseServerSession(PromiseParameters parameters)
        {
            _Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            InternalState = new State();
        }

        public PromiseServerSession(State state, PromiseParameters parameters) : this(parameters)
        {
            InternalState = state ?? throw new ArgumentNullException(nameof(state));
        }

        public new class State : EscrowInitiator.State
        {
            public EncryptedSignature[][] EncryptedSignatures // 2D
            {
                get; set;
            }

            public PromiseServerStates Status
            {
                get; set;
            }
            public uint256 FakeIndexesHash
            {
                get;
                set;
            }
            public int ETag
            {
                get;
                set;
            }
        }

        public State GetInternalState()
        {
            var state = Serializer.Clone(InternalState);
            return state;
        }

        protected new State InternalState
        {
            get
            {
                return (State)base.InternalState;
            }
            set
            {
                base.InternalState = value;
            }
        }


        private readonly PromiseParameters _Parameters;
        public PromiseParameters Parameters
        {
            get
            {
                return _Parameters;
            }
        }

        public override void ConfigureEscrowedCoin(uint160 channelId, ScriptCoin escrowedCoin, Key escrowKey, Script redeemDestination)
        {
            AssertState(PromiseServerStates.WaitingEscrow);
            base.ConfigureEscrowedCoin(channelId, escrowedCoin, escrowKey, redeemDestination);
            InternalState.Status = PromiseServerStates.WaitingHashes;
        }


        public ServerCommitment[][] SignHashes(SignaturesRequest sigRequest)
        {
            // Almost done, just need to confirm a typo and a function.
            // Step 5

            if (sigRequest == null)
                throw new ArgumentNullException(nameof(sigRequest));

            var hashesCount = sigRequest.Hashes.Select(a => a.Length).Sum();
            if (hashesCount != Parameters.GetTotalTransactionsCount())
                throw new ArgumentException($"Incorrect number of hashes, expected {Parameters.GetTotalTransactionsCount()}");

            AssertState(PromiseServerStates.WaitingHashes);

            var promises = new ServerCommitment[Parameters.PaymentsCount][];
            // list of sigmas
            var encryptedSignatures = new EncryptedSignature[Parameters.PaymentsCount][];
            var previousSolutions = new byte[Parameters.GetTotalTransactionsCountPerLevel()][];
            previousSolutions = previousSolutions.Select(a => new byte[0]).ToArray(); // Initialize to empty array of bytes
            for (int i = 0; i < Parameters.PaymentsCount; i++)
            {
                promises[i] = new ServerCommitment[sigRequest.Hashes[i].Length]; // Initialization
                encryptedSignatures[i] = new EncryptedSignature[promises[i].Length]; // Initialization
                for (int j = 0; j < promises[i].Length; j++)
                {
                    var hash = sigRequest.Hashes[i][j];
                    var ecdsa = InternalState.EscrowKey.Sign(hash);
                    var ecdsaDER = ecdsa.ToDER();
                    // This can be replaced by "Utils.xxx" if padding is not important.
                    var key = (new XORKey(Parameters.ServerKey)).ToBytes(); // Generates a random epsilon.
                    previousSolutions[j] = Utils.Combine(key, previousSolutions[j]);
                    var paddedSolutions = new PuzzleSolution(Utils.Combine(NBitcoin.Utils.ToBytes((uint)i, true), NBitcoin.Utils.ToBytes((uint)j, true), previousSolutions[j]));
                    // This function needs to be approved "XOR".
                    var promise = XORKey.XOR(paddedSolutions._Value.ToByteArrayUnsigned(), ecdsaDER);
                    PuzzleSolution solution = new PuzzleSolution(key); // Epsilon
                    var puzzle = Parameters.ServerKey.GeneratePuzzle(ref solution);
                    promises[i][j] = new ServerCommitment(puzzle.PuzzleValue, promise);
                    encryptedSignatures[i][j] = new EncryptedSignature(ecdsa, hash, solution);
                }
            }

            InternalState.Status = PromiseServerStates.WaitingRevelation;
            InternalState.EncryptedSignatures = encryptedSignatures;
            InternalState.FakeIndexesHash = sigRequest.FakeIndexesHash;
            return promises;
        }

        public ServerCommitmentsProof CheckRevelation(ClientRevelation revelation, IDestination cashoutDestination, FeeRate feeRate)
        {
            // See notes in the function below
            if (cashoutDestination == null)
                throw new ArgumentNullException(nameof(cashoutDestination));
            return CheckRevelation(revelation, cashoutDestination.ScriptPubKey, feeRate);
        }

        public ServerCommitmentsProof CheckRevelation(ClientRevelation revelation, Script cashoutDestination, FeeRate feeRate)
        {
            /*
              * Steps 7, 9
              * Almost ready, just need to figure out:
              * - The CashOutFormat for the validation of RealSet.
              * - How to get the cashoutDestination and the feeRate,
              *   for now I pass them in like in "CreateSignatureRequest"
              *   from ClientSession.
             */

            if (revelation == null)
                throw new ArgumentNullException(nameof(revelation));

            var saltCount = revelation.Salts.Select(a => a.Length).Sum();
            if (saltCount != Parameters.GetTotalFakeTransactionsCount() || revelation.FakeIndexes.Length != Parameters.FakeTransactionCountPerLevel)
                throw new ArgumentNullException($"The revelation should contains {Parameters.GetTotalFakeTransactionsCount()} salts and {Parameters.FakeTransactionCountPerLevel} indices");

            var variationCount = revelation.FeeVariations.Select(a => a.Length).Sum();
            if (variationCount != Parameters.GetTotalRealTransactionsCount())
                throw new ArgumentNullException($"The revelation should contains {Parameters.GetTotalRealTransactionsCount()} fee variations");

            AssertState(PromiseServerStates.WaitingRevelation);

            var indexSalt = revelation.IndexesSalt;
            if (InternalState.FakeIndexesHash != PromiseUtils.HashIndexes(ref indexSalt, revelation.FakeIndexes))
            {
                throw new PuzzleException("Invalid index salt");
            }

            Transaction cashout = new Transaction();
            // TODO: Figure out the cashout format for j Bitcoins
            cashout.AddInput(new TxIn(InternalState.EscrowedCoin.Outpoint));
            cashout.Inputs[0].ScriptSig = new Script(
                Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                Op.GetPushOp(InternalState.EscrowedCoin.Redeem.ToBytes())
                );
            cashout.AddOutput(new TxOut(InternalState.EscrowedCoin.Amount, cashoutDestination));
            cashout.Outputs[0].Value -= feeRate.GetFee(cashout.GetVirtualSize());


            var solutions = new PuzzleSolution[Parameters.PaymentsCount][];
            var RealIndexes = Enumerable.Range(0, Parameters.GetTotalTransactionsCountPerLevel()).Where(a => !revelation.FakeIndexes.Contains(a)).ToArray();
            for (int i = 0; i < solutions.Length; i++)
            {
                // Checking valid Transactions
                for (int j = 0; j < Parameters.RealTransactionCountPerLevel; j++)
                {
                    var feeVariation = revelation.FeeVariations[i][j];
                    var encrypted = InternalState.EncryptedSignatures[i][RealIndexes[j]];
                    // Check if this function approved!
                    var actualSignedHash = Parameters.CreateRealHash(cashout, InternalState.EscrowedCoin, feeVariation);
                    if (actualSignedHash != encrypted.SignedHash)
                        throw new PuzzleException("Incorrect feeVariation provided");
                }
                // Checking Fake Transactions
                solutions[i] = new PuzzleSolution[Parameters.FakeTransactionCountPerLevel]; // Initialization
                for (int j = 0; j < solutions[i].Length; j++)
                {
                    var salt = revelation.Salts[i][j];
                    var encrypted = InternalState.EncryptedSignatures[i][revelation.FakeIndexes[j]];
                    var actualSignedHash = Parameters.CreateFakeHash(salt);
                    if (actualSignedHash != encrypted.SignedHash)
                        throw new PuzzleException("Incorrect salt provided");
                    solutions[i][j] = encrypted.PuzzleSolution;
                }
            }

            // We can throw away the fake puzzles
            InternalState.EncryptedSignatures = InternalState.EncryptedSignatures.Select(a => a.Where((e, i) => !revelation.FakeIndexes.Contains(i)).ToArray()).ToArray();

            // Step 9
            var quotients = new Quotient[Parameters.PaymentsCount][];
            for (int i = 0; i < quotients.Length; i++)
            {
                quotients[i] = new Quotient[Parameters.RealTransactionCountPerLevel - 1];
                for (int j = 0; j < quotients[i].Length; j++)
                {
                    var a = InternalState.EncryptedSignatures[i][j].PuzzleSolution._Value;
                    var b = InternalState.EncryptedSignatures[i][j + 1].PuzzleSolution._Value;
                    quotients[i][j] = new Quotient(b.Multiply(a.ModInverse(Parameters.ServerKey._Key.Modulus)).Mod(Parameters.ServerKey._Key.Modulus));
                }
            }

            InternalState.FakeIndexesHash = null;
            InternalState.Status = PromiseServerStates.Completed;
            return new ServerCommitmentsProof(solutions.ToArray(), quotients);
        }


        public PromiseServerStates Status
        {
            get
            {
                return InternalState.Status;
            }
        }

        private void AssertState(PromiseServerStates state)
        {
            if (state != InternalState.Status)
                throw new InvalidOperationException($"Invalid state, actual {InternalState.Status} while expected is {state}");
        }

        public override LockTime GetLockTime(CycleParameters cycle)
        {
            return cycle.GetTumblerLockTime();
        }
    }
}
