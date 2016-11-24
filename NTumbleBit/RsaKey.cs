﻿using NTumbleBit.BouncyCastle.Asn1;
using NTumbleBit.BouncyCastle.Asn1.Pkcs;
using NTumbleBit.BouncyCastle.Asn1.X509;
using NTumbleBit.BouncyCastle.Crypto;
using NTumbleBit.BouncyCastle.Crypto.Engines;
using NTumbleBit.BouncyCastle.Crypto.Generators;
using NTumbleBit.BouncyCastle.Crypto.Parameters;
using NTumbleBit.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.Pkcs;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NTumbleBit
{
	public class RsaKey
	{
		static BigInteger RSA_F4 = BigInteger.ValueOf(65537);
		internal readonly RsaPrivateCrtKeyParameters _Key;

		public RsaKey()
		{
			var gen = new RsaKeyPairGenerator();
			gen.Init(new RsaKeyGenerationParameters(RSA_F4, NBitcoinSecureRandom.Instance, KeySize, 2)); // See A.15.2 IEEE P1363 v2 D1 for certainty parameter
			var pair = gen.GenerateKeyPair();
			_Key = (RsaPrivateCrtKeyParameters)pair.Private;
			_PubKey = new RsaPubKey((RsaKeyParameters)pair.Public);
		}

		public RsaKey(byte[] bytes)
		{
			if(bytes == null)
				throw new ArgumentNullException("bytes");
			try
			{
				DerSequence seq2 = GetRSASequence(bytes);
				var s = new RsaPrivateKeyStructure(seq2);
				_Key = new RsaPrivateCrtKeyParameters(s.Modulus, s.PublicExponent, s.PrivateExponent, s.Prime1, s.Prime2, s.Exponent1, s.Exponent2, s.Coefficient);
				_PubKey = new RsaPubKey(new RsaKeyParameters(false, s.Modulus, s.PublicExponent));
			}
			catch(Exception)
			{
				throw new FormatException("Invalid RSA Key");
			}
		}

		internal byte[] Sign(byte[] data)
		{
			if(data == null)
				throw new ArgumentNullException("data");
			if(data.Length != KeySize / 8)
				throw new ArgumentException("data should have a size of " + KeySize + " bits");

			var engine = new RsaCoreEngine();
			engine.Init(true, _Key);
			return engine.ConvertOutput(engine.ProcessBlock(engine.ConvertInput(data, 0, data.Length)));
		}

		public PuzzleSolution SolvePuzzle(Puzzle puzzle)
		{
			if(puzzle == null)
				throw new ArgumentNullException("puzzle");

			return new PuzzleSolution(Decrypt(puzzle._Value));
		}

		internal BigInteger Decrypt(BigInteger encrypted)
		{
			if(encrypted == null)
				throw new ArgumentNullException("encrypted");
			if(encrypted.CompareTo(_Key.Modulus) >= 0)
				throw new DataLengthException("input too large for RSA cipher.");

			RsaCoreEngine engine = new RsaCoreEngine();
			engine.Init(false, this._Key);
			return engine.ProcessBlock(encrypted);
		}

		internal static DerSequence GetRSASequence(byte[] bytes)
		{
			Asn1InputStream decoder = new Asn1InputStream(bytes);
			var seq = (DerSequence)decoder.ReadObject();
			if(!((DerInteger)seq[0]).Value.Equals(BigInteger.Zero))
				throw new Exception();
			if(!((DerSequence)seq[1])[0].Equals(algID.ObjectID) ||
			   !((DerSequence)seq[1])[1].Equals(algID.Parameters))
				throw new Exception();
			var seq2b = (DerOctetString)seq[2];
			decoder = new Asn1InputStream(seq2b.GetOctets());
			var seq2 = (DerSequence)decoder.ReadObject();
			return seq2;
		}

		readonly RsaPubKey _PubKey;
		public RsaPubKey PubKey
		{
			get
			{
				return _PubKey;
			}
		}

		public byte[] ToBytes()
		{
			RsaPrivateKeyStructure keyStruct = new RsaPrivateKeyStructure(
				_Key.Modulus,
				_Key.PublicExponent,
				_Key.Exponent,
				_Key.P,
				_Key.Q,
				_Key.DP,
				_Key.DQ,
				_Key.QInv);

			var privInfo = new PrivateKeyInfo(algID, keyStruct.ToAsn1Object());
			return privInfo.ToAsn1Object().GetEncoded();
		}

		internal static AlgorithmIdentifier algID = new AlgorithmIdentifier(
					new DerObjectIdentifier("1.2.840.113549.1.1.1"), DerNull.Instance);
		public static readonly int KeySize = 2048;
	}
}
