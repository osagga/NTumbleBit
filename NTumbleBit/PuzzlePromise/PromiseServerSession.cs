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

        public override void ConfigureTumblerCashOutAddress(Script tumblerAddress)
        {
            base.ConfigureTumblerCashOutAddress(tumblerAddress);
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
            // 2D array of pairs of puzzles and promises (z_i, c_i).
            var promises = new ServerCommitment[Parameters.PaymentsCount][];
            // 2D array of encrypted signatures with their solutions.
            var encryptedSignatures = new EncryptedSignature[Parameters.PaymentsCount][];
            // 1-D array is used to store the epsilons for each column to be used when Hashing.
            var previousSolutions = new byte[Parameters.GetTotalTransactionsCountPerLevel()][];

            previousSolutions = previousSolutions.Select(a => new byte[0]).ToArray(); // Initialize to empty array of bytes
            for (int i = 0; i < Parameters.PaymentsCount; i++)
            {
                promises[i] = new ServerCommitment[sigRequest.Hashes[i].Length]; // Initialization
                encryptedSignatures[i] = new EncryptedSignature[promises[i].Length]; // Initialization
                for (int j = 0; j < promises[i].Length; j++)
                {
                    var hash = sigRequest.Hashes[i][j];
                    // Sign the hash value
                    var ecdsa = InternalState.EscrowKey.Sign(hash);
                    // Convert Signature to Bytes.
                    var ecdsaDER = ecdsa.ToDER();
                    // This can be replaced by "Utils.GenerateEncryptableInteger(Key)" if padding when XORing is not important.
                    var key = (new XORKey(Parameters.ServerKey)).ToBytes(); // This just generates a random epsilon.
                    // Append the new epsilon to the list of epsilons we have for that column to create "epsilon_{i-1,j}|| . . . , epsilon_{0,j}".
                    previousSolutions[j] = Utils.Combine(key, previousSolutions[j]);
                    // Create the padded solution with the following format "i||j||epsilon_{i,j}||epsilon_{i-1,j}|| . . . , epsilon_{0,j}"
                    var paddedSolutions = new PuzzleSolution(Utils.Combine(NBitcoin.Utils.ToBytes((uint)i, true), NBitcoin.Utils.ToBytes((uint)j, true), previousSolutions[j]));
                    // Hash and XOR the padded solution with the signature we have.
                    var promise = XORKey.XOR(paddedSolutions._Value.ToByteArrayUnsigned(), ecdsaDER); // This function needs to be approved "XOR".
                    PuzzleSolution solution = new PuzzleSolution(key); // Epsilon
                    // Encrypt the epsilon value using RSA
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

        public ServerCommitmentsProof CheckRevelation(ClientRevelation revelation, FeeRate feeRate)
        {
            /*
              * Steps 7, 9
              * TODO [DONE]:
              * Almost ready, just need to do the following:
              * - Make the function 'getCashOut' to check the validation of RealSet.
              * - BobCashoutDestination should be part of the revelation
             */

            if (revelation == null)
                throw new ArgumentNullException(nameof(revelation));

            var saltCount = revelation.Salts.Select(a => a.Length).Sum();
            if (saltCount != Parameters.GetTotalFakeTransactionsCount() || revelation.FakeIndexes.Length != Parameters.FakeTransactionCountPerLevel)
                throw new ArgumentNullException($"The revelation should contains {Parameters.GetTotalFakeTransactionsCount()} salts and {Parameters.FakeTransactionCountPerLevel} indices");

            var variationCount = revelation.FeeVariations.Select(a => a.Length).Sum();
            if (variationCount != Parameters.GetTotalRealTransactionsCount())
                throw new ArgumentNullException($"The revelation should contains {Parameters.GetTotalRealTransactionsCount()} fee variations");

            var bobCashoutDestination = revelation.BobCashoutDestination;
            if (bobCashoutDestination == null)
                throw new ArgumentNullException($"The revelation should contains {nameof(bobCashoutDestination)}");

            AssertState(PromiseServerStates.WaitingRevelation);

            var indexSalt = revelation.IndexesSalt;
            if (InternalState.FakeIndexesHash != PromiseUtils.HashIndexes(ref indexSalt, revelation.FakeIndexes))
            {
                throw new PuzzleException("Invalid index salt");
            }

            var solutions = new PuzzleSolution[Parameters.PaymentsCount][];
            var RealIndexes = Enumerable.Range(0, Parameters.GetTotalTransactionsCountPerLevel()).Where(a => !revelation.FakeIndexes.Contains(a)).ToArray();
            for (int i = 0; i < solutions.Length; i++)
            {
                Transaction cashout = new Transaction();
                cashout.AddInput(new TxIn(InternalState.EscrowedCoin.Outpoint));
                cashout.Inputs[0].ScriptSig = new Script(
                    Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                    Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                    Op.GetPushOp(InternalState.EscrowedCoin.Redeem.ToBytes())
                );
                cashout.Inputs[0].Witnessify();
                /* NOTE: This value should be "Denomination * i" so that it's more adjustable.
                    - The problem though is that 'Denomination' is not accessible from here,
                        So maybe that should be added to the promiseParameters?
                */
                cashout.AddOutput(new TxOut(Money.Coins( (i+1) * Parameters.Denomination), bobCashoutDestination));
                cashout.Outputs[0].Value -= feeRate.GetFee(cashout.GetVirtualSize());
                cashout.AddOutput(InternalState.EscrowedCoin.Amount - Money.Coins((i+1) * Parameters.Denomination), InternalState.TumblerCashOutDestination);

                // Checking valid Transactions
                for (int j = 0; j < Parameters.RealTransactionCountPerLevel; j++)
                {
                    var feeVariation = revelation.FeeVariations[i][j];
                    var encrypted = InternalState.EncryptedSignatures[i][RealIndexes[j]];
                    // TODO: Implement the function below
                    // Transaction cashout = getCashOut(InternalState.EscrowedCoin.Amount, i, cashoutDestination, InternalState.TumblerRedeemAddress);
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
                throw new InvalidStateException($"Invalid state, actual {InternalState.Status} while expected is {state}");
        }

        public override LockTime GetLockTime(CycleParameters cycle)
        {
            return cycle.GetTumblerLockTime();
        }
    }
}
