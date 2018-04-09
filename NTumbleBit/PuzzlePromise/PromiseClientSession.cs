﻿using NBitcoin;
using NBitcoin.Crypto;
using NTumbleBit.BouncyCastle.Math;
using NTumbleBit.PuzzleSolver;
using System;
using System.Collections.Generic;
using System.Linq;

namespace NTumbleBit.PuzzlePromise
{
    public enum PromiseClientStates
    {
        WaitingEscrow,
        WaitingSignatureRequest,
        WaitingCommitments,
        WaitingCommitmentsProof,
        Completed
    }

    public class PromiseClientSession : EscrowReceiver
    {
        private abstract class HashBase
        {
            public ServerCommitment Commitment
            {
                get;
                internal set;
            }
            public abstract uint256 GetHash();
            public int Index
            {
                get; set;
            }
        }

        private class RealHash : HashBase
        {
            public RealHash(Transaction tx, ScriptCoin coin)
            {
                _BaseTransaction = tx;
                _Escrow = coin;
            }
            private readonly ScriptCoin _Escrow;
            private readonly Transaction _BaseTransaction;
            public Money FeeVariation
            {
                get; set;
            }

            public override uint256 GetHash()
            {
                var escrow = EscrowScriptPubKeyParameters.GetFromCoin(_Escrow);
                var coin = _Escrow.Clone();
                coin.OverrideScriptCode(escrow.GetInitiatorScriptCode());
                return GetTransaction().GetSignatureHash(coin, SigHash.All);
            }

            public Transaction GetTransaction()
            {
                var clone = _BaseTransaction.Clone();
                clone.Outputs[0].Value -= FeeVariation;
                return clone;
            }
        }

        private class FakeHash : HashBase
        {
            public FakeHash(PromiseParameters parameters)
            {
                Parameters = parameters ?? throw new ArgumentNullException(nameof(parameters));
            }
            public uint256 Salt
            {
                get; set;
            }
            public PromiseParameters Parameters
            {
                get;
                private set;
            }
            public override uint256 GetHash()
            {
                return Parameters.CreateFakeHash(Salt);
            }
        }

        public PromiseClientSession(PromiseParameters parameters = null)
        {
            _Parameters = parameters ?? new PromiseParameters();
            InternalState = new State();
        }

        public PromiseParameters Parameters
        {
            get
            {
                return _Parameters;
            }
        }

        public new class State : EscrowReceiver.State
        {
            public Transaction Cashout
            {
                get;
                set;
            }
            public ServerCommitment[][] Commitments //2D
            {
                get;
                set;
            }
            public uint256[][] Salts //2D
            {
                get;
                set;
            }
            public uint256 IndexSalt
            {
                get;
                set;
            }
            public Money[][] FeeVariations //2D
            {
                get;
                set;
            }

            public Quotient[][] Quotients //2D
            {
                get;
                set;
            }
            public PromiseClientStates Status
            {
                get;
                set;
            }
            public int[] FakeColumns // This should be 1D
            {
                get; set;
            }
            public BlindFactor[] BlindFactors // 1D, Now we have a list of 'r' values
            {
                get;
                set;
            }
        }

        private readonly PromiseParameters _Parameters;
        private HashBase[][] _Hashes; // The list of Hashes (Beta_i in the paper)
        private byte[][][] _Epsilons; // The list of Hashes (Beta_i in the paper)

        public PromiseClientSession(PromiseParameters parameters, State state) : this(parameters)
        {
            if (state == null)
                return;
            InternalState = Serializer.Clone(state);
            if (InternalState.Commitments != null)
            {
                _Hashes = new HashBase[parameters.PaymentsCount][];
                for (int i = 0; i < _Hashes.Length; i++)
                {
                    _Hashes[i] = new HashBase[InternalState.Commitments[i].Length];
                    int fakeJ = 0, realJ = 0;
                    for (int j = 0; j < _Hashes[i].Length; j++)
                    {
                        HashBase hash = null;
                        if (InternalState.FakeColumns != null && InternalState.FakeColumns.Contains(j))
                        {
                            hash = new FakeHash(parameters)
                            {
                                Salt = InternalState.Salts[i][fakeJ++]
                            };
                        }
                        else
                        {
                            // TODO: Figure out a way to generate this Cashout dynamically on the given 'i' BTCs
                            // OR we can save internally a 2D array of the Cashouts and just refrence the needed one from here.
                            hash = new RealHash(InternalState.Cashout, InternalState.EscrowedCoin)
                            {
                                FeeVariation = InternalState.FeeVariations[i][realJ++]
                            };
                        }
                        hash.Index = j;
                        hash.Commitment = InternalState.Commitments[i][j];
                        _Hashes[i][j] = hash;
                    }
                }
            }
        }

        public State GetInternalState()
        {
            State state = Serializer.Clone(InternalState);
            state.Salts = null;
            state.FeeVariations = null;
            state.Commitments = null;
            if (_Hashes != null)
            {
                var commitments = new ServerCommitment[_Hashes.Length][];
                var salts = new uint256[_Hashes.Length][];
                var feeVariations = new Money[_Hashes.Length][];
                for (int i = 0; i < _Hashes.Length; i++)
                {
                    salts[i] = new uint256[_Parameters.FakeTransactionCountPerLevel];
                    feeVariations[i] = new Money[_Parameters.RealTransactionCountPerLevel];
                    commitments[i] = new ServerCommitment[_Hashes[i].Length];
                    int fakeJ = 0, realJ = 0;
                    for (int j = 0; j < _Hashes[i].Length; j++)
                    {
                        if (_Hashes[i][j] is FakeHash fake)
                            salts[i][fakeJ++] = fake.Salt;

                        if (_Hashes[i][j] is RealHash real)
                            feeVariations[i][realJ++] = real.FeeVariation;

                        commitments[i][j] = _Hashes[i][j].Commitment;
                    }
                }
                state.Salts = salts;
                state.FeeVariations = feeVariations;
                state.Commitments = commitments;
            }
            return state;
        }

        public override void ConfigureEscrowedCoin(ScriptCoin escrowedCoin, Key escrowKey)
        {
            AssertState(PromiseClientStates.WaitingEscrow);
            base.ConfigureEscrowedCoin(escrowedCoin, escrowKey);
            InternalState.Status = PromiseClientStates.WaitingSignatureRequest;
        }

        public SignaturesRequest CreateSignatureRequest(IDestination cashoutDestination, FeeRate feeRate)
        {
            if (cashoutDestination == null)
                throw new ArgumentNullException(nameof(cashoutDestination));
            return CreateSignatureRequest(cashoutDestination.ScriptPubKey, feeRate);
        }
        public SignaturesRequest CreateSignatureRequest(Script cashoutDestination, FeeRate feeRate)
        {
            // Steps 2-4
            // Almost done, just need to figure out the Transaction CashOut things.
            // NOTE: When this function is called, it's assumed that the TumblerEscrowRedeem (change) address is saved in the internal state.

            if (cashoutDestination == null)
                throw new ArgumentNullException(nameof(cashoutDestination));
            if (feeRate == null)
                throw new ArgumentNullException(nameof(feeRate));

            AssertState(PromiseClientStates.WaitingSignatureRequest);

            Transaction cashout = new Transaction();
            /*
            TODO: Make the format below a function like what we do in the Server side!
            cashout.AddInput(new TxIn(InternalState.EscrowedCoin.Outpoint));
            cashout.Inputs[0].ScriptSig = new Script(
                Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                Op.GetPushOp(TrustedBroadcastRequest.PlaceholderSignature),
                Op.GetPushOp(InternalState.EscrowedCoin.Redeem.ToBytes())
                );
            cashout.Inputs[0].Witnessify();
            
            TODO: Here we should have two outputs:
                - The first is 'i' to the 'cashoutDestination'
                - The second should be 'InternalState.EscrowedCoin.Amount - i' to 'InternalState.change_address'

            cashout.AddOutput(new TxOut(InternalState.EscrowedCoin.Amount, cashoutDestination));

            TODO: We should save this fee value for each level of payments, so that we can also send it to the Tumbler to figure out
            The exact value for the fee. (Maybe this can be deterministically calculated on the server side? I'm not sure)

            cashout.Outputs[0].Value -= feeRate.GetFee(cashout.GetVirtualSize());

            TODO: If each payment level requires a different cashOut, then this
            should be moved to the first loop.
            */

            HashBase[][] hashes = new HashBase[_Parameters.PaymentsCount][]; //2D
            for (int i = 0; i < _Parameters.PaymentsCount; i++)
            {
                // TODO: Cashout will be defined here for each payment level
                hashes[i] = new HashBase[_Parameters.GetTotalTransactionsCountPerLevel()];
                for (int j = 0; j < Parameters.RealTransactionCountPerLevel; j++)
                { 
                    RealHash h = new RealHash(cashout, InternalState.EscrowedCoin)
                    {
                        FeeVariation = Money.Satoshis(j)
                    };
                    hashes[i][j] = h;
                }
                for (int j = Parameters.RealTransactionCountPerLevel; j < hashes[i].Length; j++)
                {
                    FakeHash h = new FakeHash(Parameters)
                    {
                        Salt = new uint256(RandomUtils.GetBytes(32))
                    };
                    hashes[i][j] = h;
                }

            }
            _Hashes = hashes;

            // Under the assumption that given the same seed the Shuffle will be deterministic.
            // TODO: Verify this in Debugging or a unit test.
            var shuffleSeed = RandomUtils.GetInt32();
            for (int i = 0; i < _Parameters.PaymentsCount; i++)
                NBitcoin.Utils.Shuffle(_Hashes[i], shuffleSeed);

            for (int i = 0; i < _Parameters.PaymentsCount; i++)
                for (int j = 0; j < _Hashes[i].Length; j++)
                    _Hashes[i][j].Index = j;

            var fakeIndices = _Hashes.First().OfType<FakeHash>().Select(h => h.Index).ToArray();
            uint256 indexSalt = null;
            var request = new SignaturesRequest
            {
                // This looks cool, but double check the use of Select in debugging.
                Hashes = _Hashes.Select(h => (h.Select(k => k.GetHash()).ToArray())).ToArray(),
                FakeIndexesHash = PromiseUtils.HashIndexes(ref indexSalt, fakeIndices),
            };
            InternalState.IndexSalt = indexSalt;
            /*
                TODO:
                Add the cashOutDestination to the InternalState so that it can be later sent through the reveal step.
                "InternalState.cashOutDestination = cashOutDestination;"
             */
            InternalState.Cashout = cashout.Clone();
            InternalState.Status = PromiseClientStates.WaitingCommitments;
            InternalState.FakeColumns = fakeIndices;
            return request;
        }

        public ClientRevelation Reveal(ServerCommitment[][] commitments)
        {
            // Step 6 
            if (commitments == null)
                throw new ArgumentNullException(nameof(commitments));

            var CommitmentsCount = commitments.Select(a => a.Length).Sum(); // sums the number of commitments
            var TransactionsCountPerLevel = Parameters.GetTotalTransactionsCountPerLevel();

            if (CommitmentsCount != Parameters.GetTotalTransactionsCount())
                throw new ArgumentException($"Expecting {Parameters.GetTotalTransactionsCount()} commitments");

            AssertState(PromiseClientStates.WaitingCommitments);

            uint256[][] salts = new uint256[_Parameters.PaymentsCount][];
            Money[][] feeVariations = new Money[_Parameters.PaymentsCount][];

            List<int> fakeIndices = new List<int>();

            // This figures out the indices of fake hashes.
            for (int i = 0; i < TransactionsCountPerLevel; i++)
            {
                if (_Hashes.First()[i] is FakeHash)
                    fakeIndices.Add(i);
            }

            for (int i = 0; i < _Parameters.PaymentsCount; i++)
            {
                salts[i] = new uint256[_Parameters.FakeTransactionCountPerLevel];
                feeVariations[i] = new Money[_Parameters.RealTransactionCountPerLevel];
                int fakeJ = 0, realJ = 0;
                for (int j = 0; j < TransactionsCountPerLevel; j++)
                {
                    if (_Hashes[i][j] is FakeHash fake)
                        salts[i][fakeJ++] = fake.Salt;

                    if (_Hashes[i][j] is RealHash real)
                        feeVariations[i][realJ++] = real.FeeVariation;

                    _Hashes[i][j].Commitment = commitments[i][j];
                }

            }
            InternalState.Status = PromiseClientStates.WaitingCommitmentsProof;
            // TODO: Add the cashoutDestintation to the things Bob reveals to the Tumbler.
            return new ClientRevelation(fakeIndices.ToArray(), InternalState.IndexSalt, salts, feeVariations);
        }

        public PuzzleValue[] CheckCommitmentProof(ServerCommitmentsProof proof)
        {
            // steps 8, 10, 12
            if (proof == null)
                throw new ArgumentNullException(nameof(proof));

            var FakeSolutionsCount = proof.FakeSolutions.Select(a => a.Length).Sum(); // sums the number of FakeSolutions.
            if (FakeSolutionsCount != Parameters.GetTotalFakeTransactionsCount())
                throw new ArgumentException($"Expecting {Parameters.GetTotalFakeTransactionsCount()} solutions");

            var QuotientsCount = proof.Quotients.Select(a => a.Length).Sum(); // sums the number of Quotients.
            if (QuotientsCount != (Parameters.GetTotalRealTransactionsCount() - _Parameters.PaymentsCount)) // this is Q * (mu - 1)
                throw new ArgumentException($"Expecting {(Parameters.GetTotalRealTransactionsCount() - _Parameters.PaymentsCount)} quotients");

            AssertState(PromiseClientStates.WaitingCommitmentsProof);
            var previousSolutions = new byte[Parameters.FakeTransactionCountPerLevel][];
            previousSolutions = previousSolutions.Select(a => new byte[0]).ToArray(); // Initialize to empty
            for (int i = 0; i < _Hashes.Length; i++)
            {
                var fakeHashes = _Hashes[i].OfType<FakeHash>().ToArray();
                for (int j = 0; j < fakeHashes.Length; j++)
                {
                    // TODO: check that the solutions are lined up in same order as the hashes.
                    var fakeHash = fakeHashes[j];
                    var solution = proof.FakeSolutions[i][j];

                    if (solution._Value.CompareTo(Parameters.ServerKey._Key.Modulus) >= 0)
                        throw new PuzzleException("Solution bigger than modulus");

                    if (!new Puzzle(Parameters.ServerKey, fakeHash.Commitment.Puzzle).Verify(solution))
                        throw new PuzzleException("Invalid puzzle solution");

                    previousSolutions[j] = Utils.Combine(solution.ToBytes(), previousSolutions[j]);
                    
                    var paddedSolution = new PuzzleSolution(Utils.Combine(NBitcoin.Utils.ToBytes((uint)i, true), NBitcoin.Utils.ToBytes((uint)fakeHash.Index, true), previousSolutions[j]));
                    if (!IsValidSignature(paddedSolution, fakeHash, out ECDSASignature sig))
                        throw new PuzzleException("Invalid ECDSA signature");
                }
            }
            // Step 10
            for (int i = 0; i < _Hashes.Length; i++)
            {
                var realHashes = _Hashes[i].OfType<RealHash>().ToArray();
                for (int j = 1; j < realHashes.Length; j++)
                {
                    var q = proof.Quotients[i][j - 1]._Value;
                    var p1 = realHashes[j - 1].Commitment.Puzzle._Value;
                    var p2 = realHashes[j].Commitment.Puzzle._Value;
                    var p22 = p1.Multiply(Parameters.ServerKey.Encrypt(q)).Mod(Parameters.ServerKey._Key.Modulus);
                    if (!p2.Equals(p22))
                        throw new PuzzleException("Invalid quotient");
                }
            }
            _Hashes = _Hashes.Select(a => a.OfType<RealHash>().ToArray()).ToArray(); // we do not need the fake one anymore
            InternalState.FakeColumns = null;
            InternalState.Quotients = proof.Quotients;

            // Step 12
            // Maybe move this step outside such that we can blind and send puzzles one by one.
            BlindFactor[] blindFactors = new BlindFactor[_Hashes.Length];
            PuzzleValue[] blindedPuzzles = new PuzzleValue[_Hashes.Length];

            for (int i = 0; i < _Hashes.Length; i++)
            {
                var puzzleToSolve = _Hashes[i].OfType<RealHash>().First().Commitment.Puzzle;
                blindedPuzzles[i] = new Puzzle(Parameters.ServerKey, puzzleToSolve).Blind(ref blindFactors[i]).PuzzleValue;
            }

            InternalState.BlindFactors = blindFactors;
            InternalState.Status = PromiseClientStates.Completed;
            return blindedPuzzles;
        }

        private bool IsValidSignature(PuzzleSolution solution, HashBase hash, out ECDSASignature signature)
        {
            // NOTE: The XOR operation below hashes the first input by default. So Whatever is passed there will be hased first then XORed.
            signature = null;
            var escrow = EscrowScriptPubKeyParameters.GetFromCoin(InternalState.EscrowedCoin);
            try
            {
                var key = solution._Value.ToByteArrayUnsigned();
                var sig = XORKey.XOR(key, hash.Commitment.Promise);
                signature = new ECDSASignature(sig);
                var ok = escrow.Initiator.Verify(hash.GetHash(), signature);
                if (!ok)
                    signature = null;
                return ok;
            }
            catch
            {
            }
            return false;
        }

        internal IEnumerable<Transaction> GetSignedTransactions(PuzzleSolution solution, int paymentNumber)
        {
            /*
               * TODO: I modified this to reflect the change below, please TEST and DEBUG THIS!
               * parameter "paymentNumber" indicates which j payment this is.
               * NOTE: In order to solve the puzzle using the "solution", we need the previous solution 
               * to get the signatures.
            *      - To solve this problem, we need to define an internal structure similar to "_Hashes" that holds the keys (epsilons).
                        - This structure will be populated everytime we recover an epsilon from "cumul" below, and should be used to lookup
                            - previous epsilons when computing the solution for the current puzzle.
               *  
             */
            if (solution == null)
                throw new ArgumentNullException(nameof(solution));
            AssertState(PromiseClientStates.Completed);
            solution = solution.Unblind(Parameters.ServerKey, InternalState.BlindFactors[paymentNumber]);
            BigInteger cumul = solution._Value;
            var hashes = _Hashes[paymentNumber].OfType<RealHash>().ToArray();
            for (int i = 0; i < Parameters.RealTransactionCountPerLevel; i++)
            {
                var hash = hashes[i];
                
                var quotient = i == 0 ? BigInteger.One : InternalState.Quotients[paymentNumber][i - 1]._Value;
                
                cumul = cumul.Multiply(quotient).Mod(Parameters.ServerKey._Key.Modulus); // Epsilon_{paymentNumber}{i}
                _Epsilons[paymentNumber][i] = cumul.ToByteArrayUnsigned();
                
                var prevEpsilons = getPrevEpsilons(paymentNumber, i);
                var key = Utils.Combine(NBitcoin.Utils.ToBytes((uint)paymentNumber, true), NBitcoin.Utils.ToBytes((uint)i, true), prevEpsilons);

                // TODO: Need to fix how the solution is recovered given how we need the previous solutions to get the current one.
                
                solution = new PuzzleSolution(key);
                
                if (!IsValidSignature(solution, hash, out ECDSASignature tumblerSig))
                    continue;
                
                var transaction = hash.GetTransaction();
                var bobSig = transaction.SignInput(InternalState.EscrowKey, InternalState.EscrowedCoin);
				transaction.Inputs[0].WitScript = new WitScript(
					Op.GetPushOp(new TransactionSignature(tumblerSig, SigHash.All).ToBytes()),
					Op.GetPushOp(bobSig.ToBytes()),
					Op.GetPushOp(InternalState.EscrowedCoin.Redeem.ToBytes())
					);
				//transaction is already witnessified
				if(transaction.Inputs.AsIndexedInputs().First().VerifyScript(InternalState.EscrowedCoin))
					yield return transaction;
            }
        }

        public Transaction GetSignedTransaction(PuzzleSolution solution, int paymentNumber)
        {
            var tx = GetSignedTransactions(solution, paymentNumber).FirstOrDefault();
            if (tx == null)
                throw new PuzzleException($"Wrong solution for the puzzle {paymentNumber}");
            return tx;
        }

        public byte[] getPrevEpsilons(int PaymentNumber, int RealTransactionHash){
            // TODO: Check by debugging that this function actually combines all the epsiolns in the specified colomn and returns it.
            // TODO: Add a unit test.
            var prevEpsilonsCombined = new byte[] {};
            for (int i = PaymentNumber; i >= 0; i--){
                prevEpsilonsCombined = Utils.Combine(prevEpsilonsCombined, _Epsilons[i][RealTransactionHash]);
            }
            return prevEpsilonsCombined;
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

        public PromiseClientStates Status
        {
            get
            {
                return InternalState.Status;
            }
        }

        private void AssertState(PromiseClientStates state)
		{
			if(state != InternalState.Status)
				throw new InvalidStateException("Invalid state, actual " + InternalState.Status + " while expected is " + state);
		}
    }
}
