using NBitcoin;
using NTumbleBit.ClassicTumbler;
using NTumbleBit.PuzzleSolver;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace NTumbleBit
{
    public abstract class EscrowReceiver : IEscrow
    {
		public class State
		{
			public ScriptCoin EscrowedCoin
			{
				get;
				set;
			}
			public Key EscrowKey
			{
				get;
				set;
			}

			/// <summary>
			/// Identify the channel to the tumbler
			/// </summary>
			public uint160 ChannelId
			{
				get;
				set;
			}
			// NOTE: This field is used to store the address in which the Tumbler wants to receive its change at.
			public Script TumblerCashoutDestination
			{
				get;
				set;
			}
            // NOTE: This field is used to store the address in which Alice wants to receive its change at.
            public Script AliceCashoutDestination
            {
                get;
                set;
            }
        }

		protected State InternalState
		{
			get; set;
		}

		public uint160 Id
		{
			get
			{
				return InternalState.ChannelId;
			}
		}

		public void SetChannelId(uint160 channelId)
		{
            InternalState.ChannelId = channelId ?? throw new ArgumentNullException(nameof(channelId));
		}
		public virtual void ConfigureEscrowedCoin(ScriptCoin escrowedCoin, Key escrowKey)
		{
            InternalState.EscrowKey = escrowKey ?? throw new ArgumentNullException(nameof(escrowKey));
			InternalState.EscrowedCoin = escrowedCoin ?? throw new ArgumentNullException(nameof(escrowedCoin));
		}

		public virtual void ConfigureTumblerCashOutAddress(Script tumblerCashoutAddress)
		{
            InternalState.TumblerCashoutDestination = tumblerCashoutAddress ?? throw new ArgumentNullException(nameof(tumblerCashoutAddress));
		}

        public virtual void ConfigureAliceCashOutAddress(Script aliceCashoutAddress)
        {
            InternalState.AliceCashoutDestination = aliceCashoutAddress ?? throw new ArgumentNullException(nameof(aliceCashoutAddress));
        }

        public ScriptCoin EscrowedCoin
		{
			get
			{
				return InternalState.EscrowedCoin;
			}
		}
	}
}
