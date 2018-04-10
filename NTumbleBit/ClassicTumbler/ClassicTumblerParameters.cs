using NBitcoin;
using NBitcoin.Crypto;
using NTumbleBit.ClassicTumbler.Client;
using NTumbleBit.PuzzlePromise;
using NTumbleBit.PuzzleSolver;
using System;
using System.Linq;
using TumbleBitSetup;

namespace NTumbleBit.ClassicTumbler
{
    public class ClassicTumblerParameters : IBitcoinSerializable
	{
		const int LAST_VERSION = 1;
		public ClassicTumblerParameters()
		{
			var solver = new SolverParameters();
			FakePuzzleCount = solver.FakePuzzleCount;
			RealPuzzleCount = solver.RealPuzzleCount;

			var promise = new PromiseParameters();
			FakeTransactionCount = promise.FakeTransactionCountPerLevel;
            RealTransactionCount = promise.RealTransactionCountPerLevel;
			FakeFormat = promise.FakeFormat;

			Denomination = Money.Coins(1.0m);
			Fee = Money.Coins(0.001m);
			CycleGenerator = new OverlappedCycleGenerator();
		}


		uint _Version = LAST_VERSION;
		public uint Version
		{
			get
			{
				return _Version;
			}
			set
			{
				_Version = value;
			}
		}

		Network _Network;
		public Network Network
		{
			get
			{
				return _Network;
			}
			set
			{
				_Network = value;
			}
		}


		OverlappedCycleGenerator _CycleGenerator;
		public OverlappedCycleGenerator CycleGenerator
		{
			get
			{
				return _CycleGenerator;
			}
			set
			{
				_CycleGenerator = value;
			}
		}


		RSAKeyData _ServerKey;
		public RSAKeyData ServerKey
		{
			get
			{
				return _ServerKey;
			}
			set
			{
				_ServerKey = value;
			}
		}


		RSAKeyData _VoucherKey;
		public RSAKeyData VoucherKey
		{
			get
			{
				return _VoucherKey;
			}
			set
			{
				_VoucherKey = value;
			}
		}


		Money _Denomination;
		public Money Denomination
		{
			get
			{
				return _Denomination;
			}
			set
			{
				_Denomination = value;
			}
		}

		internal string PrettyPrint()
		{
			//Strip keys so we can read
			var parameters = this.Clone();
			parameters.ServerKey = null;
			parameters.VoucherKey = null;
			return Serializer.ToString(parameters, parameters.Network, true);
		}

		Money _Fee;
		public Money Fee
		{
			get
			{
				return _Fee;
			}
			set
			{
				_Fee = value;
			}
		}

        int _FakePuzzleCount;
		public int FakePuzzleCount
		{
			get
			{
				return _FakePuzzleCount;
			}
			set
			{
				_FakePuzzleCount = value;
			}
		}


		int _RealPuzzleCount;
		public int RealPuzzleCount
		{
			get
			{
				return _RealPuzzleCount;
			}
			set
			{
				_RealPuzzleCount = value;
			}
		}
		
		int _BobPaymentsCount;
		public int BobPaymentsCount
		{
			get
			{
				return _BobPaymentsCount;
			}
			set
			{
				_BobPaymentsCount = value;
			}
		}

		int _FakeTransactionCount;
		public int FakeTransactionCount
		{
			get
			{
				return _FakeTransactionCount;
			}
			set
			{
				_FakeTransactionCount = value;
			}
		}


		int _RealTransactionCount;
		public int RealTransactionCount
		{
			get
			{
				return _RealTransactionCount;
			}
			set
			{
				_RealTransactionCount = value;
			}
		}


		uint256 _FakeFormat;
		public uint256 FakeFormat
		{
			get
			{
				return _FakeFormat;
			}
			set
			{
				_FakeFormat = value;
			}
		}

		public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWrite(ref _Version);
			if(_Version != LAST_VERSION)
				throw new FormatException($"Tumbler is running an invalid version ({_Version} while expected is {LAST_VERSION})");
			stream.ReadWriteC(ref _Network);
			stream.ReadWrite(ref _CycleGenerator);
			stream.ReadWrite(ref _ServerKey);
			stream.ReadWrite(ref _VoucherKey);
			stream.ReadWriteC(ref _Denomination);
			stream.ReadWriteC(ref _Fee);
			stream.ReadWrite(ref _BobPaymentsCount);
			stream.ReadWrite(ref _FakePuzzleCount);
			stream.ReadWrite(ref _RealPuzzleCount);
			stream.ReadWrite(ref _FakeTransactionCount);
			stream.ReadWrite(ref _RealTransactionCount);
			stream.ReadWriteC(ref _ExpectedAddress);
		}

        public bool Check(PromiseParameters promiseParams)
		{
			// return promiseParams.FakeTransactionCountPerLevel == FakeTransactionCount &&
			// 	promiseParams.RealTransactionCountPerLevel == RealTransactionCount &&
			// 	promiseParams.PaymentsCount == PaymentsCount;
			return promiseParams.FakeTransactionCountPerLevel == FakeTransactionCount &&
				promiseParams.RealTransactionCountPerLevel == RealTransactionCount;
		}

		public bool Check(SolverParameters solverParams)
		{
			return solverParams.FakePuzzleCount == FakePuzzleCount &&
				solverParams.RealPuzzleCount == RealPuzzleCount;
		}

		public SolverParameters CreateSolverParamaters()
		{
			/*
		TODO:
			- We need to add a definition to "AlicePaymentsCount" in the current class.
			- When this is called, it's assumed that the Value of "AlicePaymentsCount" is set.
			- We also need to define the corresponding fields in the class "SolverParameters"
				- "PaymentsCount" or "AlicePaymentsCount": This should reflect the total amount of Q BTCs alice has escrowed.
				- "TotalSolvedPuzzles": This should reflect the current total number of puzzles Alice got the solutions to.
					- This value is bounded by "PaymentsCount" as the maximun number.
			 */
			return new SolverParameters
			{
				// TODO: Need to add AlicePaymentAmount here
				FakePuzzleCount = FakePuzzleCount,
				RealPuzzleCount = RealPuzzleCount,
				ServerKey = ServerKey.PublicKey
			};
		}

		public PromiseParameters CreatePromiseParamaters()
		{
			/*
		TODO: [DONE]
			- We need to add a definition to "BobPaymentsCount" in the current class.
			- When this is called, it's assumed that the Value of "BobPaymentsCount" is set.
			- We also need to define the corresponding field in the class "PromiseParameters"
				- We can either call is "PaymentsCount" or "BobPaymentsCount".
			 */
			return new PromiseParameters
			{
                FakeFormat = FakeFormat,
				FakeTransactionCountPerLevel = FakeTransactionCount,
				RealTransactionCountPerLevel = RealTransactionCount,
				PaymentsCount = BobPaymentsCount,
				ServerKey = ServerKey.PublicKey
			};
		}


		public override bool Equals(object obj)
		{
			ClassicTumblerParameters item = obj as ClassicTumblerParameters;
			if(item == null)
				return false;
			return GetHash().Equals(item.GetHash());
		}

		public bool IsStandard()
		{
			return
				this.Version == LAST_VERSION &&
				this.VoucherKey.CheckKey() &&
				this.ServerKey.CheckKey() &&
				this.FakePuzzleCount == 285 &&
				this.RealPuzzleCount == 15 &&
				this.RealTransactionCount == 42 &&
				this.FakeTransactionCount == 42 &&
				this.Fee < this.Denomination &&
				this.FakeFormat == new uint256(Enumerable.Range(0, 32).Select(o => o == 0 ? (byte)0 : (byte)1).ToArray());

		}


		string _ExpectedAddress = "";
		public string ExpectedAddress
		{
			get
			{
				return _ExpectedAddress;
			}
			set
			{
				_ExpectedAddress = value;
			}
		}


		public uint160 GetHash()
		{
			return Hashes.Hash160(this.ToBytes());
		}

		public static bool operator ==(ClassicTumblerParameters a, ClassicTumblerParameters b)
		{
			if(System.Object.ReferenceEquals(a, b))
				return true;
			if(((object)a == null) || ((object)b == null))
				return false;
			return a.GetHash() == b.GetHash();
		}

		public static bool operator !=(ClassicTumblerParameters a, ClassicTumblerParameters b)
		{
			return !(a == b);
		}

		public static uint160 ExtractHashFromUrl(Uri serverUrl)
		{
			var prefix = "/api/v1/tumblers/";
			var path = new UriBuilder(serverUrl).Path;
			if(!path.StartsWith(prefix, StringComparison.Ordinal) || path.Length != prefix.Length + 20 * 2)
			{
				throw new FormatException("invalid tumbler uri");
			}
			return new uint160(path.Substring(prefix.Length, 20 * 2));
		}

		public override int GetHashCode()
		{
			return GetHash().GetHashCode();
		}

		public int CountEscrows(Transaction tx, Identity identity)
		{
			// TODO: Understand what does this function do.
			var amount = identity == Identity.Bob ? Denomination : Denomination + Fee;
			return tx.Outputs.Where(o => o.Value == amount).Count();
		}
	}

	public class RSAKeyData : IBitcoinSerializable
	{

		RsaPubKey _PublicKey;
		public RsaPubKey PublicKey
		{
			get
			{
				return _PublicKey;
			}
			set
			{
				_PublicKey = value;
			}
		}


		PermutationTestProof _PermutationTestProof;
		public PermutationTestProof PermutationTestProof
		{
			get
			{
				return _PermutationTestProof;
			}
			set
			{
				_PermutationTestProof = value;
			}
		}


		PoupardSternProof _PoupardSternProof;
		public PoupardSternProof PoupardSternProof
		{
			get
			{
				return _PoupardSternProof;
			}
			set
			{
				_PoupardSternProof = value;
			}
		}

		public void ReadWrite(BitcoinStream stream)
		{
			stream.ReadWriteC(ref _PublicKey);
			stream.ReadWriteC(ref _PermutationTestProof);
			stream.ReadWriteC(ref _PoupardSternProof);
		}


		public static readonly PoupardSternSetup PoupardSetup = new PoupardSternSetup()
		{
			KeySize = RsaKey.KeySize,
			SecurityParameter = 128,
			PublicString = new uint256("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").ToBytes(lendian: true)
		};

		public static readonly PermutationTestSetup PermutationSetup = new PermutationTestSetup()
		{
			KeySize = RsaKey.KeySize,
			SecurityParameter = 128,
			PublicString = new uint256("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f").ToBytes(lendian: true),
			Alpha = 65537
		};

		public bool CheckKey()
		{
			return
				PoupardSternProof != null && _PermutationTestProof != null &&
				PoupardStern.VerifyPoupardStern(_PublicKey._Key, PoupardSternProof, PoupardSetup) &&
				PermutationTest.VerifyPermutationTest(_PublicKey._Key, PermutationTestProof, PermutationSetup);
		}
	}
}
