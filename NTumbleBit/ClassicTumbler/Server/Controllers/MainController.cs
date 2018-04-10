using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using NBitcoin;
using NBitcoin.Crypto;
using NTumbleBit.ClassicTumbler.Server.Models;
using NTumbleBit.Logging;
using NTumbleBit.PuzzlePromise;
using NTumbleBit.PuzzleSolver;
using NTumbleBit.Services;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

// For more information on enabling Web API for empty projects, visit http://go.microsoft.com/fwlink/?LinkID=397860

namespace NTumbleBit.ClassicTumbler.Server.Controllers
{
    public class MainController : Controller
	{
		public MainController(TumblerRuntime runtime, CustomThreadPool threadPool)
		{
            _Runtime = runtime ?? throw new ArgumentNullException(nameof(runtime));
			_Repository = new ClassicTumblerRepository(_Runtime);
			_ThreadPool = threadPool;
		}

		CustomThreadPool _ThreadPool;



		private readonly TumblerRuntime _Runtime;
		public TumblerRuntime Runtime
		{
			get
			{
				return _Runtime;
			}
		}
		public Tracker Tracker
		{
			get
			{
				return _Runtime.Tracker;
			}
		}

		public ExternalServices Services
		{
			get
			{
				return _Runtime.Services;
			}
		}

		ClassicTumblerRepository _Repository;
		public ClassicTumblerRepository Repository
		{
			get
			{
				return _Repository;
			}
		}


		public ClassicTumblerParameters Parameters
		{
			get
			{
				return _Runtime.ClassicTumblerParameters;
			}
		}

		[HttpGet("api/v1/tumblers/{tumblerId}/parameters")]
		public ClassicTumblerParameters GetParameters(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			return tumblerId;
		}

		[HttpGet("api/v1/tumblers/{tumblerId}/vouchers")]
		public UnsignedVoucherInformation AskUnsignedVoucher(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var height = Services.BlockExplorerService.GetCurrentHeight();
			var cycleParameters = Parameters.CycleGenerator.GetRegisteringCycle(height);
			PuzzleSolution solution = null;
			var puzzle = Parameters.VoucherKey.PublicKey.GeneratePuzzle(ref solution);
            var cycle = cycleParameters.Start;
            var signature = Runtime.VoucherKey.Sign(NBitcoin.Utils.ToBytes((uint)cycle, true), out uint160 nonce);
			return new UnsignedVoucherInformation
			{
				CycleStart = cycle,
				Nonce = nonce,
				Puzzle = puzzle.PuzzleValue,
				EncryptedSignature = new XORKey(solution).XOR(signature)
			};
		}


		[HttpGet("api/v1/tumblers/{tumblerId}/clientchannels/{cycleStart}")]
		public TumblerEscrowKeyResponse RequestTumblerEscrowKey(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleStart)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var height = Services.BlockExplorerService.GetCurrentHeight();
			var cycle = GetCycle(cycleStart);
            var key = Repository.GetNextKey(cycle.Start, out int keyIndex);
            if (!cycle.IsInPhase(CyclePhase.ClientChannelEstablishment, height))
				throw new ActionResultException(BadRequest("invalid-phase"));
			return new TumblerEscrowKeyResponse { PubKey = key.PubKey, KeyIndex = keyIndex };
		}

		private CycleParameters GetCycle(int cycleStart)
		{
			try
			{
				return Parameters.CycleGenerator.GetCycle(cycleStart);
			}
			catch(InvalidOperationException)
			{
				Logs.Tumbler.LogDebug($"Invalid cycle received {cycleStart}");
				throw new ActionResultException(BadRequest("invalid-cycle"));
			}
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/clientchannels/confirm")]
		public async Task<IActionResult> BeginSignVoucher(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			[FromBody]SignVoucherRequest request)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			if(request.UnsignedVoucher == null)
				throw new ActionResultException(BadRequest("Missing UnsignedVoucher"));
			if(request.MerkleProof == null)
				throw new ActionResultException(BadRequest("Missing MerkleProof"));
			if(request.Transaction == null)
				throw new ActionResultException(BadRequest("Missing Transaction"));
			if(request.ClientEscrowKey == null)
				throw new ActionResultException(BadRequest("Missing ClientEscrowKey"));
			if(request.ChannelId == null)
				throw new ActionResultException(BadRequest("Missing ChannelId"));

			var cycle = GetCycle(request.Cycle);
			var height = Services.BlockExplorerService.GetCurrentHeight();
			if(!cycle.IsInPhase(CyclePhase.ClientChannelEstablishment, height))
			{
				throw new ActionResultException(BadRequest("invalid-phase"));
			}

			if(request.MerkleProof.PartialMerkleTree
				.GetMatchedTransactions()
				.FirstOrDefault() != request.Transaction.GetHash() || !request.MerkleProof.Header.CheckProofOfWork())
			{
				Logs.Tumbler.LogDebug("Invalid transaction merkle proof");
				throw new ActionResultException(BadRequest("invalid-merkleproof"));
			}

			var confirmations = Services.BlockExplorerService.GetBlockConfirmations(request.MerkleProof.Header.GetHash());
			if((confirmations < Parameters.CycleGenerator.FirstCycle.SafetyPeriodDuration))
			{
				Logs.Tumbler.LogDebug("Not enough confirmations");
				throw new ActionResultException(BadRequest("not-enough-confirmation"));
			}

			var transaction = request.Transaction;
			if(transaction.Outputs.Count > 2)
			{
				Logs.Tumbler.LogDebug("Incorrect number of outputs");
				throw new ActionResultException(BadRequest("invalid-transaction"));
			}

			var key = Repository.GetKey(cycle.Start, request.KeyReference);
			if(Repository.IsUsed(cycle.Start, request.ChannelId))
				throw new ActionResultException(BadRequest("duplicate-query"));

			var expectedEscrow = new EscrowScriptPubKeyParameters(request.ClientEscrowKey, key.PubKey, cycle.GetClientLockTime());

			/*
				TODO:
				Here, the Tumbler doesn't know the expected amount that Alice should put in the TxOut (it's up to her), but the tumbler
				knows for sure that the amount should be at least 'Parameters.Fee', plus maybe some multiple of the 'Parameters.Denomination'?
				So I can do any of the following here:
					- I can change the expectedTxOut to be only the Fee amount, and then later check If 'TxOut.Value' is >= 'expectedTxOut.Value'
						- I can also add a new check to see if the (amount - Fee) is a multiple of the Denomination?
			
			 */
			// TODO: Instead of passing 'Denomination' + 'Fee', we only pass 'Fee'
			var expectedTxOut = new TxOut(Parameters.Denomination + Parameters.Fee, expectedEscrow.ToScript().WitHash.ScriptPubKey.Hash);
			var escrowedCoin =
				transaction
				.Outputs
				.AsCoins()
				// TODO: This would change to '>=' instead of '=='
				.Where(c => c.TxOut.Value == expectedTxOut.Value
							&& c.TxOut.ScriptPubKey == expectedTxOut.ScriptPubKey)
				.Select(c => c.ToScriptCoin(expectedEscrow.ToScript()))
				.FirstOrDefault();
			// TODO: Here we need to extract AlicePaymentsCount as "transaction.Outputs.AsCoins().FirstOrDefault().TxOut.Value" (Debug this to check)
			// TODO: Add a new function 'CheckTxValue(int TxValue)' that checks if the (TxValue/Denomination) is an integer and > 0
			// (we would pass "AlicePaymentsCount" here)
			if(escrowedCoin == null)
			{
				Logs.Tumbler.LogDebug("Could not find escrowed coin");
				throw new ActionResultException(BadRequest("invalid-transaction"));
			}
			/*
			TODO:
				- Before this call, it's expected that "Parameters.AlicePaymentsCount" is set to the amount 'Q' that 
					Alice has specified in the 'request.AlicePaymentsCount'
				- "Parameters.AlicePaymentsCount = AlicePaymentsCount"
			 */
			var solverServerSession = new SolverServerSession(Runtime.TumblerKey, Parameters.CreateSolverParamaters());
			solverServerSession.SetChannelId(request.ChannelId);
			solverServerSession.ConfigureEscrowedCoin(escrowedCoin, key);
			await Services.BlockExplorerService.TrackAsync(escrowedCoin.ScriptPubKey);

			//Without this one, someone could spam the nonce db by replaying this request with different channelId
			if(!Repository.MarkUsedNonce(cycle.Start, Hashes.Hash160(escrowedCoin.Outpoint.ToBytes())))
				throw new ActionResultException(BadRequest("duplicate-query"));

			AssertNotDuplicateQuery(cycle.Start, request.ChannelId);

			Repository.Save(cycle.Start, solverServerSession);

			QueueWork(async () =>
			{
				try
				{

					if(!await Services.BlockExplorerService.TrackPrunedTransactionAsync(request.Transaction, request.MerkleProof))
					{
						Logs.Tumbler.LogDebug("Invalid merkleproof for " + transaction.GetHash());
						return;
					}
					var correlation = GetCorrelation(solverServerSession);
					Tracker.AddressCreated(cycle.Start, TransactionType.ClientEscrow, escrowedCoin.ScriptPubKey, correlation);
					Tracker.TransactionCreated(cycle.Start, TransactionType.ClientEscrow, request.Transaction.GetHash(), correlation);
					var solution = request.UnsignedVoucher.WithRsaKey(Runtime.VoucherKey.PubKey).Solve(Runtime.VoucherKey);
					Repository.SaveSignedVoucher(cycle.Start, request.ChannelId, solution);
					Logs.Tumbler.LogInformation($"Cycle {cycle.Start} Proof of Escrow signed for " + transaction.GetHash());
				}
				catch(Exception ex)
				{
					Logs.Tumbler.LogCritical(new EventId(), ex, "Unhandled error during while signing voucher");
				}
			});
			return Ok();
		}

		[HttpGet("api/v1/tumblers/{tumblerId}/clientchannels/confirm/{cycleId}/{channelId}")]
		public PuzzleSolution EndSignVoucher(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			int cycleId)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			if(channelId == null)
				throw new ArgumentNullException(nameof(channelId));
			var cycle = GetCycle(cycleId);
			var height = Services.BlockExplorerService.GetCurrentHeight();
			if(!cycle.IsInPhase(CyclePhase.ClientChannelEstablishment, height))
			{
				throw new ActionResultException(BadRequest("invalid-phase"));
			}
			return Repository.GetSignedVoucher(cycleId, channelId);
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/channels/beginopen")]
		public async Task<uint160.MutableUint160> BeginOpenChannel(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			[FromBody] OpenChannelRequest request)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var height = Services.BlockExplorerService.GetCurrentHeight();
			if(Repository.IsUsed(request.CycleStart, request.Nonce))
				throw new ActionResultException(BadRequest("duplicate-query"));
			var cycle = GetCycle(request.CycleStart);
			if(!cycle.IsInPhase(CyclePhase.TumblerChannelEstablishment, height))
				throw new ActionResultException(BadRequest("invalid-phase"));
			var fee = await Services.FeeService.GetFeeRateAsync();

			try
			{
				if(!Repository.MarkUsedNonce(request.CycleStart, request.Nonce))
					throw new ActionResultException(BadRequest("duplicate-query"));
				if(!Parameters.VoucherKey.PublicKey.Verify(request.Signature, NBitcoin.Utils.ToBytes((uint)request.CycleStart, true), request.Nonce))
					throw new ActionResultException(BadRequest("incorrect-voucher"));

				var escrowKey = new Key();

                var escrow = new EscrowScriptPubKeyParameters
                {
                    LockTime = cycle.GetTumblerLockTime(),
                    Receiver = request.EscrowKey,
                    Initiator = escrowKey.PubKey
                };
                var channelId = new uint160(RandomUtils.GetBytes(20));
				Logs.Tumbler.LogInformation($"Cycle {cycle.Start} Asked to open channel");

				/*
					TODO:
					This is the Escrow Transaction for Bob, I should change the value here to be 'Q'
					instead of Parameters.Denomination. The value Q can be passed along with the request
					to open the channel for Bob.

					NOTE (Problem maybe?):
						Should there be an upper limit to how much (Q) Bob can ask for? He can get all the Tumbler's Money
						if he wants.
				*/
				// TODO: This first parameter should change to 'Q' that Bob specifies.
				var bobRequestedPaymentCount = request.RequestedPaymentsCount;
				//TODO: Double check that you can multiply a Money Object with an Int
				var txOut = new TxOut(new Money( Parameters.Denomination * bobRequestedPaymentCount), escrow.ToScript().WitHash.ScriptPubKey.Hash);
				
				// NOTE: This checks if the Tumbler has enough funds to give 'Q' of the denomination to Bob
				var unused = Services.WalletService.FundTransactionAsync(txOut, fee)
					.ContinueWith(async (Task<Transaction> task) =>
					{
						try
						{
							var tx = await task.ConfigureAwait(false);
							var correlation = new CorrelationId(channelId);
							Tracker.TransactionCreated(cycle.Start, TransactionType.TumblerEscrow, tx.GetHash(), correlation);

							//Logging/Broadcast per funding TX one time
							if(Repository.MarkUsedNonce(cycle.Start, new uint160(tx.GetHash().ToBytes().Take(20).ToArray())))
							{
								var bobCount = Parameters.CountEscrows(tx, Client.Identity.Bob);
								Logs.Tumbler.LogInformation($"Cycle {cycle.Start} channel created {tx.GetHash()} with {bobCount} users");
								await Services.BroadcastService.BroadcastAsync(tx).ConfigureAwait(false);
							}

							await Services.BlockExplorerService.TrackAsync(txOut.ScriptPubKey).ConfigureAwait(false);
							Tracker.AddressCreated(cycle.Start, TransactionType.TumblerEscrow, txOut.ScriptPubKey, correlation);
							var coin = tx.Outputs.AsCoins().First(o => o.ScriptPubKey == txOut.ScriptPubKey && o.TxOut.Value == txOut.Value);
							/*
								TODO:
									- We need to set 'BobPaymentsCount' here before we create the instance of the PromiseServerSession.
										- One way to do this is by setting:
											"Parameters.BobPaymentsCount = Q"
												- 'Q' here references to the number of BTCs that Bob asked for above, and it should be the 
													same as the number of BTCs the Tumbler escrowed.
							 */
							Parameters.BobPaymentsCount = bobRequestedPaymentCount;
							var session = new PromiseServerSession(Parameters.CreatePromiseParamaters());
							// TODO: This is the way the Tumbler uses to generate new address, we need to use something similar to generate
							// the address the Tumbler sends to Bob to receive the change of the escrow transaction.
							var redeem = await Services.WalletService.GenerateAddressAsync().ConfigureAwait(false);

							session.ConfigureEscrowedCoin(channelId, coin.ToScriptCoin(escrow.ToScript()), escrowKey, redeem.ScriptPubKey);
							var redeemTx = session.CreateRedeemTransaction(fee);
							Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.TumblerRedeem, correlation, redeemTx);
							Repository.Save(cycle.Start, session);
							Tracker.AddressCreated(cycle.Start, TransactionType.TumblerRedeem, redeem.ScriptPubKey, correlation);
						}
						catch(Exception ex)
						{
							Logs.Tumbler.LogCritical(new EventId(), ex, "Error during escrow transaction callback");
						}
					});
				return channelId.AsBitcoinSerializable();
			}
			catch(NotEnoughFundsException ex)
			{
				Logs.Tumbler.LogInformation(ex.Message);
				throw new ActionResultException(BadRequest("tumbler-insufficient-funds"));
			}
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/channels/{cycleId}/{channelId}/endopen")]
		public async Task<TumblerEscrowData> EndOpenChannel(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId)
		{
			var height = Services.BlockExplorerService.GetCurrentHeight();
			var cycle = GetCycle(cycleId);
			if(!cycle.IsInPhase(CyclePhase.TumblerChannelEstablishment, height))
				throw new ActionResultException(BadRequest("invalid-phase"));

			var session = GetPromiseServerSession(cycle.Start, channelId, CyclePhase.TumblerChannelEstablishment, false);
			if(session == null)
				return null;

			

			var tx = (await Services.BlockExplorerService
							.GetTransactionsAsync(session.EscrowedCoin.TxOut.ScriptPubKey, true))
							.FirstOrDefault(t => t.Transaction.GetHash() == session.EscrowedCoin.Outpoint.Hash);
			
			if(session == null || tx == null)
				return null;
			
			AssertNotDuplicateQuery(cycle.Start, channelId);
			// TODO: Check if we actually want this to be "ConfigureAwait(false)"
			var cashout = await Services.WalletService.GenerateAddressAsync().ConfigureAwait(false);
			// TODO: Check the way I'm getting the 'correlation' here
			var correlation = new CorrelationId(channelId);
			Tracker.AddressCreated(cycle.Start, TransactionType.TumblerCashout, cashout.ScriptPubKey, correlation);

			return new TumblerEscrowData()
			{
				Transaction = tx.Transaction,
				OutputIndex = (int)session.EscrowedCoin.Outpoint.N,
				EscrowInitiatorKey = session.GetInternalState().EscrowKey.PubKey,
				// NOTE: I added this new field here
				ChangeAddress = cashout.ScriptPubKey,
				MerkleProof = tx.MerkleProof
			};
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/channels/{cycleId}/{channelId}/signhashes")]
		public PuzzlePromise.ServerCommitment[][] SignHashes(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]SignaturesRequest sigReq)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetPromiseServerSession(cycleId, channelId, CyclePhase.TumblerChannelEstablishment);
			AssertNotDuplicateQuery(cycleId, channelId);
			var hashes = session.SignHashes(sigReq);
			Repository.Save(cycleId, session);
			return hashes;
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/channels/{cycleId}/{channelId}/checkrevelation")]
		public ServerCommitmentsProof CheckRevelationPromise(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]PuzzlePromise.ClientRevelation revelation)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetPromiseServerSession(cycleId, channelId, CyclePhase.TumblerChannelEstablishment);
			AssertNotDuplicateQuery(cycleId, channelId);

            // TODO: Bob's key should be part of the revelation, also in the InternalState, we should have the change address for the Tumbler.
            var proof = session.CheckRevelation(revelation);

			Repository.Save(cycleId, session);
			return proof;
		}

		private PromiseServerSession GetPromiseServerSession(int cycleId, uint160 channelId, CyclePhase expectedPhase, bool throws = true)
		{
			if(channelId == null)
				throw new ArgumentNullException(nameof(channelId));
			var height = Services.BlockExplorerService.GetCurrentHeight();
			var session = Repository.GetPromiseServerSession(cycleId, channelId);
			if(session == null)
			{
				if(throws)
					throw NotFound("channel-not-found").AsException();
				return null;
			}
			CheckPhase(expectedPhase, height, cycleId);
			return session;
		}

		private SolverServerSession GetSolverServerSession(int cycleId, uint160 channelId, CyclePhase expectedPhase)
		{
			if(channelId == null)
				throw new ArgumentNullException(nameof(channelId));
			var height = Services.BlockExplorerService.GetCurrentHeight();
			var session = Repository.GetSolverServerSession(cycleId, channelId);
			if(session == null)
				throw NotFound("channel-not-found").AsException();
			CheckPhase(expectedPhase, height, cycleId);
			return session;
		}

		private void CheckPhase(CyclePhase expectedPhase, int height, int cycleId)
		{
			CycleParameters cycle = GetCycle(cycleId);
			if(!cycle.IsInPhase(expectedPhase, height))
				throw BadRequest("invalid-phase").AsException();
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/clientchannels/{cycleId}/{channelId}/solvepuzzles")]
		public IActionResult BeginSolvePuzzles(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]PuzzleValue[] puzzles)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.PaymentPhase);
			AssertNotDuplicateQuery(cycleId, channelId);

			QueueWork(() =>
			{
				session.BeginSolvePuzzles(puzzles);
				Repository.Save(cycleId, session);
			});
			return Ok();
		}

		[HttpGet("api/v1/tumblers/{tumblerId}/clientchannels/{cycleId}/{channelId}/solvepuzzles")]
		public PuzzleSolver.ServerCommitment[] EndSolvePuzzles(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.PaymentPhase);
			if(session.Status != SolverServerStates.WaitingCommitmentDelivery)
				return null;
			AssertNotDuplicateQuery(cycleId, channelId);
			var commitments = session.EndSolvePuzzles();
			Repository.Save(cycleId, session);
			return commitments;
		}

		private void QueueWork(Action act)
		{
			var unused = _ThreadPool.DoAsync(act);
		}

		private void AssertNotDuplicateQuery(int cycleId, uint160 channelId, [CallerMemberName]string name = null)
		{
			var h = Hashes.Hash160(Encoding.UTF8.GetBytes(channelId.ToString() + name));
			if(!Repository.MarkUsedNonce(cycleId, h))
				throw new ActionResultException(BadRequest("duplicate-query"));
		}


		[HttpPost("api/v1/tumblers/{tumblerId}/clientschannels/{cycleId}/{channelId}/checkrevelation")]
		public SolutionKey[] CheckRevelationSolver(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]
			uint160 channelId,
			[FromBody]PuzzleSolver.ClientRevelation revelation)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.PaymentPhase);
			AssertNotDuplicateQuery(cycleId, channelId);
			var solutions = session.CheckRevelation(revelation);
			Repository.Save(cycleId, session);
			return solutions;
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/clientschannels/{cycleId}/{channelId}/checkblindfactors")]
		public async Task<OfferInformation> CheckBlindFactors(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]BlindFactor[] blindFactors)
		{
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.PaymentPhase);
			AssertNotDuplicateQuery(cycleId, channelId);
			var feeRate = await Services.FeeService.GetFeeRateAsync();
			var fulfillKey = session.CheckBlindedFactors(blindFactors, feeRate);
			Repository.Save(cycleId, session);
			return fulfillKey;
		}

		[HttpPost("api/v1/tumblers/{tumblerId}/clientchannels/{cycleId}/{channelId}/offer")]
		public async Task<SolutionKey[]> FulfillOffer(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]SignatureWrapper wrapper)
		{
			var signature = wrapper?.Signature;
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			if(signature == null)
				throw new ActionResultException(BadRequest("Missing Signature"));

			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.TumblerCashoutPhase);
			AssertNotDuplicateQuery(cycleId, channelId);

			var feeRate = await Services.FeeService.GetFeeRateAsync();

			if(session.Status != SolverServerStates.WaitingFulfillment)
				throw new InvalidStateException("Invalid state, actual " + session.Status + " while expected is " + SolverServerStates.WaitingFulfillment);
			
			var cycle = GetCycle(cycleId);
			var cashout = await Services.WalletService.GenerateAddressAsync();

			var fulfill = session.FulfillOffer(signature, cashout.ScriptPubKey, feeRate);
			fulfill.BroadcastAt = new LockTime(cycle.GetPeriods().Payment.End - 1);
			Repository.Save(cycle.Start, session);

			var signedOffer = session.GetSignedOfferTransaction();
			signedOffer.BroadcastAt = fulfill.BroadcastAt - 1;
			var correlation = GetCorrelation(session);

			var offerScriptPubKey = session.GetInternalState().OfferCoin.ScriptPubKey;


			await Services.BlockExplorerService.TrackAsync(offerScriptPubKey);

			Tracker.AddressCreated(cycle.Start, TransactionType.ClientOffer, offerScriptPubKey, correlation);
			Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientOffer, correlation, signedOffer);

			Tracker.AddressCreated(cycle.Start, TransactionType.ClientFulfill, cashout.ScriptPubKey, correlation);

			if(!Runtime.NoFulFill)
			{
				Services.TrustedBroadcastService.Broadcast(cycle.Start, TransactionType.ClientFulfill, correlation, fulfill);
			}
			return Runtime.Cooperative ? session.GetSolutionKeys() : new SolutionKey[0];
		}

		private static CorrelationId GetCorrelation(SolverServerSession session)
		{
			return new CorrelationId(session.Id);
		}


		[HttpPost("api/v1/tumblers/{tumblerId}/clientchannels/{cycleId}/{channelId}/escape")]
		public async Task<NoData> GiveEscapeKey(
			[ModelBinder(BinderType = typeof(TumblerParametersModelBinder))]
			ClassicTumblerParameters tumblerId,
			int cycleId,
			[ModelBinder(BinderType = typeof(UInt160ModelBinder))]  uint160 channelId,
			[FromBody]SignatureWrapper wrapper)
		{
			var clientSignature = wrapper?.Signature;
			if(tumblerId == null)
				throw new ArgumentNullException(nameof(tumblerId));
			var session = GetSolverServerSession(cycleId, channelId, CyclePhase.TumblerCashoutPhase);
			AssertNotDuplicateQuery(cycleId, channelId);

			var fee = await Services.FeeService.GetFeeRateAsync();

			var dummy = new Key().PubKey.Hash.ScriptPubKey;
			var tx = session.GetSignedEscapeTransaction(clientSignature, fee, dummy);
			var state = session.GetInternalState();

			// The previous tx is broadcastable, but let's give change to the wallet to join everything in a single transaction
			var unused = Runtime.Services.WalletService.ReceiveAsync(state.EscrowedCoin, clientSignature, state.EscrowKey, fee)
				.ContinueWith(async (Task<Transaction> task) =>
				{
					try
					{
						tx = await task.ConfigureAwait(false);
						var correlation = GetCorrelation(session);
						Tracker.AddressCreated(cycleId, TransactionType.ClientEscape, tx.Outputs[0].ScriptPubKey, correlation);
						Tracker.TransactionCreated(cycleId, TransactionType.ClientEscape, tx.GetHash(), correlation);
						if(Repository.MarkUsedNonce(cycleId, new uint160(tx.GetHash().ToBytes().Take(20).ToArray())))
						{
							Logs.Tumbler.LogInformation($"Cashing out from {tx.Inputs.Count} Alices");
							await Services.BroadcastService.BroadcastAsync(tx).ConfigureAwait(false);
						}
					}
					catch(Exception ex)
					{
						Logs.Tumbler.LogCritical(new EventId(), ex, "Error during escape transaction callback");
					}
				});

			return new NoData();
		}
	}
}
