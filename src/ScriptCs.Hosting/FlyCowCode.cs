using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using NuGet;

namespace ScriptCs.Hosting
{
    internal static class DataUtil
    {
        internal static byte[] HexStringToBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return null;
            if (hex.StartsWith("0x")) hex = hex.Substring(2);

            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }

    internal sealed class FlyCowCredentialProvider : ICredentialProvider
    {
        private readonly IEncryptionProvider _crypto = new EncryptionProvider(new DataEncoder());
        private readonly string _username;
        private readonly string _password;
        private const string Username = "Username";
        private const string Password = "Password";
        private const string FlyCowCredentials = "flyCowCredentials";

        public FlyCowCredentialProvider(ISettings settings)
        {
            _username = settings.GetValue(FlyCowCredentials, Username, false);
            _password = settings.GetValue(FlyCowCredentials, Password, false);
        }
        ICredentials ICredentialProvider.GetCredentials(Uri uri, IWebProxy proxy, CredentialType credentialType, bool retrying)
        {
            return new FlyCowCredentials(_username, _crypto.Decrypt(_password, DataUtil.HexStringToBytes(ConfigurationManager.AppSettings["FlyCowKey"]??"0x7AA78BD98799BA167A9755A1BCF4B139")));
        }
        internal static void Ensure(ISettings settings)
        {
            var u = settings.GetValue(FlyCowCredentials, Username, false);
            if (!string.IsNullOrEmpty(u))
            {
                HttpClient.DefaultCredentialProvider = new FlyCowCredentialProvider(settings);
            }
        }
    }

    internal sealed class FlyCowCredentials : ICredentials
    {
        private readonly string _username;
        private readonly string _password;

        public FlyCowCredentials(string username, string password)
        {
            _username = username;
            _password = password;
        }

        NetworkCredential ICredentials.GetCredential(Uri uri, string authType)
        {
            return new NetworkCredential(_username,_password);
        }
    }


    public interface IEncryptionProvider
    {
        string Decrypt(string tokenString);
        string Decrypt(string tokenString, byte[] key);
        string Encript(string raw);
        string Encript(string raw, byte[] key);
    }
    internal sealed class EncryptionProvider : IEncryptionProvider
    {
        private readonly IDataEncoder _encoder;
        private readonly CryptoSymmetric _crypto;
        // todo: hide it in registry
        private readonly byte[] _defaultKey = new byte[]{0xC4, 0x28, 0x5D, 0x2F, 0xBC, 0x81, 0x3E, 0x2D, 0x96, 0x24, 0x91, 0x03, 0xD3, 0x63, 0x74, 0xAD, 0x0C, 0x1F, 0x14, 0x64, 0x29, 0x58, 0xA6, 0x55, 0x0E, 0x5D, 0xF3, 0x4B, 0xF7, 0xCC, 0x9E, 0x74, 0xC8, 0x0F, 0x0B, 0xEF, 0xCF, 0x33, 0xC0, 0x41, 0xA7, 0x8B, 0x57, 0x44, 0x1A, 0x54, 0xE3, 0x71, 0xE8, 0xAE, 0x55, 0x63, 0xF2, 0xC9, 0x5D, 0x5B, 0x62, 0x1C, 0x66, 0x58, 0x17, 0xAA, 0xE3, 0xDD};

        internal EncryptionProvider(IDataEncoder encoder)
        {
            _encoder = encoder;
            _crypto = new CryptoSymmetric(CryptoSymmetric.CryptoAlgorithm.CryptoAlgorithmRijndael);
        }

        string IEncryptionProvider.Decrypt(string tokenString)
        {
            var bytes = _encoder.Decode(tokenString);
            return Encoding.UTF8.GetString(_crypto.DecryptBytes(bytes, _defaultKey));
        }
        string IEncryptionProvider.Decrypt(string tokenString, byte[] key)
        {
            var bytes = _encoder.Decode(tokenString);
            return Encoding.UTF8.GetString(_crypto.DecryptBytes(bytes, key));
        }


        string IEncryptionProvider.Encript(string raw)
        {
            var encrypted = _crypto.EncryptBytes(Encoding.UTF8.GetBytes(raw), _defaultKey);
            return _encoder.Encode(encrypted);
        }
        string IEncryptionProvider.Encript(string raw, byte[] key)
        {
            var encrypted = _crypto.EncryptBytes(Encoding.UTF8.GetBytes(raw), key);
            return _encoder.Encode(encrypted);
        }
    }

    public interface IDataEncoder
    {
        string Encode(byte[] bytes);
        byte[] Decode(string encoded);
    }
    internal sealed class DataEncoder : IDataEncoder
    {
        private static readonly char[] Base62CodingSpace = 
            "PRg3ZINxpbSWrzX0fyhE1Ul5YHd7wqFaK9uemVO2QBLDAstjJnGiTc8o46kvMC" // shuffled version of "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            .ToCharArray();

        private static readonly IDictionary<char, int> Base62CodingSpaceIndexByChar =
            Base62CodingSpace
            .Select((ch, i) => Tuple.Create(ch, i))
            .ToDictionary(t => t.Item1, t => t.Item2);


        string IDataEncoder.Encode(byte[] bytes)
        {
            if (bytes == null || bytes.Length == 0)
            {
                throw new ArgumentException("Empty value passed to be encoded");
            }

            StringBuilder sb = new StringBuilder();
            BitStream stream = new BitStream(bytes);         // Set up the BitStream
            byte[] read = new byte[1];                          // Only read 6-bit at a time
            while (true)
            {
                read[0] = 0;
                int length = stream.Read(read, 0, 6);           // Try to read 6 bits
                if (length == 6)                                // Not reaching the end
                {
                    if (read[0] >> 3 == 0x1f)            // First 5-bit is 11111
                    {
                        sb.Append(Base62CodingSpace[61]);
                        stream.Seek(-1, SeekOrigin.Current);    // Leave the 6th bit to next group
                    }
                    else if (read[0] >> 3 == 0x1e)       // First 5-bit is 11110
                    {
                        sb.Append(Base62CodingSpace[60]);
                        stream.Seek(-1, SeekOrigin.Current);
                    }
                    else                                        // Encode 6-bit
                    {
                        sb.Append(Base62CodingSpace[read[0] >> 2]);
                    }
                }
                else if (length == 0)                           // Reached the end completely
                {
                    break;
                }
                else                                            // Reached the end with some bits left
                {
                    // Padding 0s to make the last bits to 6 bit
                    sb.Append(Base62CodingSpace[read[0] >> 8 - length]);
                    break;
                }
            }
            return sb.ToString();
        }

        byte[] IDataEncoder.Decode(string encoded)
        {
            if (string.IsNullOrEmpty(encoded))
            {
                throw new ArgumentException("Empty value passed to be decoded");
            }

            // Character count
            int count = 0;

            // Set up the BitStream
            BitStream stream = new BitStream(encoded.Length * 6 / 8);

            for(var i = 0; i < encoded.Length; ++i)
            {
                var c = encoded[i];

                // Look up coding table
                int index = Base62CodingSpaceIndexByChar[c];

                // If end is reached
                if (count == encoded.Length - 1)
                {
                    // Check if the ending is good
                    int mod = (int)(stream.Position % 8);
                    if (mod == 0)
                        throw new InvalidDataException("an extra character was found");

                    if ((index >> (8 - mod)) > 0)
                        throw new InvalidDataException("invalid ending character was found");

                    stream.Write(new byte[] { (byte)(index << mod) }, 0, 8 - mod);
                }
                else
                {
                    // If 60 or 61 then only write 5 bits to the stream, otherwise 6 bits.
                    if (index == 60)
                    {
                        stream.Write(new byte[] { 0xf0 }, 0, 5);
                    }
                    else if (index == 61)
                    {
                        stream.Write(new byte[] { 0xf8 }, 0, 5);
                    }
                    else
                    {
                        stream.Write(new byte[] { (byte)index }, 2, 6);
                    }
                }
                count++;
            }

            // Dump out the bytes
            byte[] result = new byte[stream.Position / 8];
            stream.Seek(0, SeekOrigin.Begin);
            stream.Read(result, 0, result.Length * 8);
            return result;
        }
    }

    internal class BitStream : Stream
    {
        private byte[] Source { get; set; }

        /// <summary>
        /// Initialize the stream with capacity
        /// </summary>
        /// <param name="capacity">Capacity of the stream</param>
        public BitStream(int capacity)
        {
            Source = new byte[capacity];
        }

        /// <summary>
        /// Initialize the stream with a source byte array
        /// </summary>
        /// <param name="source"></param>
        public BitStream(byte[] source)
        {
            Source = source;
        }

        public override bool CanRead
        {
            get { return true; }
        }

        public override bool CanSeek
        {
            get { return true; }
        }

        public override bool CanWrite
        {
            get { return true; }
        }

        public override void Flush()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Bit length of the stream
        /// </summary>
        public override long Length
        {
            get { return Source.Length * 8; }
        }

        /// <summary>
        /// Bit position of the stream
        /// </summary>
        public override long Position { get; set; }

        /// <summary>
        /// Read the stream to the buffer
        /// </summary>
        /// <param name="buffer">Buffer</param>
        /// <param name="offset">Offset bit start position of the stream</param>
        /// <param name="count">Number of bits to read</param>
        /// <returns>Number of bits read</returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            // Temporary position cursor
            long tempPos = this.Position;
            tempPos += offset;

            // Buffer byte position and in-byte position
            int readPosCount = 0, readPosMod = 0;

            // Stream byte position and in-byte position
            long posCount = tempPos >> 3;
            int posMod = (int)(tempPos - ((tempPos >> 3) << 3));

            while (tempPos < Position + offset + count && tempPos < Length)
            {
                // Copy the bit from the stream to buffer
                if ((Source[posCount] & (0x1 << (7 - posMod))) != 0)
                {
                    buffer[readPosCount] = (byte)(buffer[readPosCount] | (0x1 << (7 - readPosMod)));
                }
                else
                {
                    buffer[readPosCount] = (byte)(buffer[readPosCount] & (0xffffffff - (0x1 << (7 - readPosMod))));
                }

                // Increment position cursors
                tempPos++;
                if (posMod == 7)
                {
                    posMod = 0;
                    posCount++;
                }
                else
                {
                    posMod++;
                }
                if (readPosMod == 7)
                {
                    readPosMod = 0;
                    readPosCount++;
                }
                else
                {
                    readPosMod++;
                }
            }
            int bits = (int)(tempPos - Position - offset);
            Position = tempPos;
            return bits;
        }

        /// <summary>
        /// Set up the stream position
        /// </summary>
        /// <param name="offset">Position</param>
        /// <param name="origin">Position origin</param>
        /// <returns>Position after setup</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            switch (origin)
            {
                case SeekOrigin.Begin:
                    {
                        Position = offset;
                        break;
                    }
                case SeekOrigin.Current:
                    {
                        Position += offset;
                        break;
                    }
                case SeekOrigin.End:
                    {
                        Position = Length + offset;
                        break;
                    }
            }
            return Position;
        }

        public override void SetLength(long value)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Write from buffer to the stream
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset">Offset start bit position of buffer</param>
        /// <param name="count">Number of bits</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            // Temporary position cursor
            long tempPos = Position;

            // Buffer byte position and in-byte position
            int readPosCount = offset >> 3, readPosMod = offset - ((offset >> 3) << 3);

            // Stream byte position and in-byte position
            long posCount = tempPos >> 3;
            int posMod = (int)(tempPos - ((tempPos >> 3) << 3));

            while (tempPos < Position + count && tempPos < Length)
            {
                // Copy the bit from buffer to the stream
                if ((buffer[readPosCount] & (0x1 << (7 - readPosMod))) != 0)
                {
                    Source[posCount] = (byte)(Source[posCount] | (0x1 << (7 - posMod)));
                }
                else
                {
                    Source[posCount] = (byte)(Source[posCount] & (0xffffffff - (0x1 << (7 - posMod))));
                }

                // Increment position cursors
                tempPos++;
                if (posMod == 7)
                {
                    posMod = 0;
                    posCount++;
                }
                else
                {
                    posMod++;
                }
                if (readPosMod == 7)
                {
                    readPosMod = 0;
                    readPosCount++;
                }
                else
                {
                    readPosMod++;
                }
            }
            Position = tempPos;
        }
    }

    internal static class CryptoAlgorithm
    {
        public const string Rc2			= "RC2";
        public const string Des			= "DES";
        public const string TripleDes	= "TRIPLEDES";
		public const string Rijndael	= "RIJNDAEL";// known as AES
        public const string Aes	= "AES";// known as RIJNDAEL
    }

	internal sealed class CryptoSymmetric { 
		#region Class Enumerations 
		/// <summary> 
		/// Enumeration of supported symmetric algorithms. 
		/// </summary> 
		public enum CryptoAlgorithm { 
			CryptoAlgorithmDes,
			CryptoAlgorithmRc2,
			CryptoAlgorithmRijndael,
			CryptoAlgorithmTripleDes 
		} 
		/// <summary> 
		/// Enumeration of supported hash algorithms. 
		/// The Hash algorithm is used to hash the Key before encyrption/decryption. 
		/// </summary> 
		public enum HashAlgorithm { 
			HashAlgorithmMd5,
			HashAlgorithmSha1,
			HashAlgorithmSha256,
			HashAlgorithmSha384,
			HashAlgorithmSha512,
			HashAlgorithmNone 
		} 
		/// <summary> 
		/// Enumeration to designate whether encryption or decryption is the 
		/// desired transformation. 
		/// </summary> 
		private enum CryptoMethod { 
			CryptoMethodEncrypt,
			CryptoMethodDecrypt 
		} 
		#endregion 

		#region Properties 
		/// <summary> 
		/// The key used for encryption/decryption. 
		/// </summary> 
		private byte[] _arrKey; 
		/// <summary> 
		/// The initialization vector used for encryption/decryption. 
		/// </summary> 
		private byte[] _arrIv; 
		/// <summary> 
		/// The symmetric algorithm service provider for encryption/decryption. 
		/// </summary> 
		private SymmetricAlgorithm _objCryptoService; 
		/// <summary> 
		/// The symmetric algorithm for encryption/decryption. 
		/// </summary> 
		private CryptoAlgorithm _algorithmId; 
		/// <summary> 
		/// The hash algorithm for hashing the key. 
		/// </summary> 
		private HashAlgorithm _hashId; 
		#endregion 

		#region Accessor Methods 
		/// <summary> 
		/// Gets or sets the encryption Key 
		/// </summary> 
		public byte[] Key { 
			get { 
				return _arrKey; 
			} 
			set { 
				// if they set this via the accessor, make sure it's legal 
				_arrKey = GetLegalKey(value); 
			} 
		} 
		/// <summary> 
		/// Gets or sets the Initialization Vector 
		/// </summary> 
		public byte[] IV { 
			get { 
				return _arrIv; 
			} 
			set { 
				// if they set this via the accessor, make sure it's valid 
				_arrIv = GetValidIV(value); 
			} 
		} 
		/// <summary> 
		/// Gets or sets the CryptoAlgorithm type 
		/// </summary> 
		public CryptoAlgorithm EncryptionAlgorithm { 
			get { 
				return _algorithmId; 
			} 
			set { 
				_algorithmId = value; 
			} 
		} 
		/// <summary> 
		/// Gets or sets the Hash Algorithm type 
		/// </summary> 
		public HashAlgorithm HashType { 
			get { 
				return _hashId; 
			} 
			set { 
				_hashId = value; 
			} 
		} 
		#endregion 

		#region Constructors 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto) { 
			// initialize 
			Initialize(crypto, HashAlgorithm.HashAlgorithmNone); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, string strKey) { 
			// initialize the encryption Key and use Key as IV 
			_arrKey = GetLegalKey(strKey); 
			_arrIv = GetValidIV(strKey); 

			// initialize 
			Initialize(crypto, HashAlgorithm.HashAlgorithmNone); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, string strKey, string strIV) { 
			// initialize the encryption Key, IV 
			_arrKey = GetLegalKey(strKey); 
			_arrIv = GetValidIV(strIV); 

			// initialize 
			Initialize(crypto, HashAlgorithm.HashAlgorithmNone); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, byte[] arrKey) { 
			// initialize the encryption Key and use Key as IV 
			_arrKey = GetLegalKey(arrKey); 
			_arrIv = GetValidIV(arrKey); 

			// initialize 
			Initialize(crypto, HashAlgorithm.HashAlgorithmNone); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, byte[] arrKey, byte[] arrIv) { 
			// initialize the encryption Key, IV 
			_arrKey = GetLegalKey(arrKey); 
			_arrIv = GetValidIV(arrIv); 

			// initialize 
			Initialize(crypto, HashAlgorithm.HashAlgorithmNone); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// The designated HashAlgorithm will be used to hash the key for encryption/decryption. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, HashAlgorithm hash) { 
			// initialize 
			Initialize(crypto, hash); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// The designated HashAlgorithm will be used to hash the key for encryption/decryption. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, HashAlgorithm hash, string strKey) { 
			// initialize the encryption Key and use Key as IV 
			_arrKey = GetLegalKey(strKey); 
			_arrIv = GetValidIV(strKey); 

			// initialize 
			Initialize(crypto, hash); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// The designated HashAlgorithm will be used to hash the key for encryption/decryption. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, HashAlgorithm hash, string strKey, string strIv) { 
			// initialize the encryption Key, IV 
			_arrKey = GetLegalKey(strKey); 
			_arrIv = GetValidIV(strIv); 

			// initialize 
			Initialize(crypto, hash); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// The designated HashAlgorithm will be used to hash the key for encryption/decryption. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, HashAlgorithm hash, byte[] arrKey) { 
			// initialize the encryption Key and use Key as IV 
			_arrKey = GetLegalKey(arrKey); 
			_arrIv = GetValidIV(arrKey); 

			// initialize 
			Initialize(crypto, hash); 
		} 
		/// <summary> 
		/// Initializes an instance of the CryptoSymmetric class. 
		/// The designated HashAlgorithm will be used to hash the key for encryption/decryption. 
		/// </summary> 
		public CryptoSymmetric(CryptoAlgorithm crypto, HashAlgorithm hash, byte[] arrKey, byte[] arrIv) { 
			// initialize the encryption Key, IV 
			_arrKey = GetLegalKey(arrKey); 
			_arrIv = GetValidIV(arrIv); 

			// initialize 
			Initialize(crypto, hash); 
		} 
		/// <summary> 
		/// Base Constructor to be used to initialize a new instance of the CryptoSymmetric class. 
		/// </summary> 
		private void Initialize(CryptoAlgorithm crypto, HashAlgorithm hash) { 
			// set the crypto algorithm, obtain the proper cryptoserviceprovider 
			_algorithmId = crypto; 
			switch (_algorithmId) { 
				case CryptoAlgorithm.CryptoAlgorithmDes: { 
					_objCryptoService = new DESCryptoServiceProvider(); 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmRc2: { 
					_objCryptoService = new RC2CryptoServiceProvider(); 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmRijndael: { 
					_objCryptoService = new RijndaelManaged(); 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmTripleDes: { 
					_objCryptoService = new TripleDESCryptoServiceProvider(); 
					break; 
				} 
			} 

			// now set the hash algorithm 
			_hashId = hash; 
		} 

		#endregion 

		#region CreateServiceProvider 
		/// <summary> 
		/// Returns the specified symmetric cryptographic service provider to enable 
		/// encryption/decryption to occur. Based on the supplied CryptoMethod, 
		/// this method will return the encryptor or decryptor. 
		/// Cipher-Block-Chaining mode is currently used for all algorithms. 
		/// </summary> 
		private ICryptoTransform CreateServiceProvider(CryptoMethod method) { 
			// if we get this far without having set a key, just throw the exception and leave 
			if (_arrKey == null) { 
				throw new CryptographicException("A key is required to " + method + " this data."); 
			} 

			// Pick the provider. 
			switch (_algorithmId) { 
				case CryptoAlgorithm.CryptoAlgorithmDes: { 
					_objCryptoService = new DESCryptoServiceProvider(); 
					_objCryptoService.Mode = CipherMode.CBC; 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmTripleDes: { 
					_objCryptoService = new TripleDESCryptoServiceProvider(); 
					_objCryptoService.Mode = CipherMode.CBC; 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmRc2: { 
					_objCryptoService = new RC2CryptoServiceProvider(); 
					_objCryptoService.Mode = CipherMode.CBC; 
					break; 
				} 
				case CryptoAlgorithm.CryptoAlgorithmRijndael: { 
					_objCryptoService = new RijndaelManaged(); 
					_objCryptoService.Mode = CipherMode.CBC; 
					break; 
				} 
			} 

			// now determine whether to send back the encryptor or decryptor 
			switch(method) { 
				case CryptoMethod.CryptoMethodEncrypt: 
					return _objCryptoService.CreateEncryptor(_arrKey, _arrIv); 

				case CryptoMethod.CryptoMethodDecrypt: 
					return _objCryptoService.CreateDecryptor(_arrKey, _arrIv); 

				default: { 
					throw new CryptographicException("Method '" + method + "' not supported."); 
				} 
			} 
		} 

		#endregion 

		#region Validation Methods for Key/IV 
		/// <summary> 
		/// Wrapper method to allow a string to be passed in to determine 
		/// if Key is legal for the specified symmetric algorithm. 
		/// Returns the byte array of the legal key. 
		/// </summary> 
		private byte[] GetLegalKey(string strKey) { 
			// return the Key 
			return GetLegalKey(Encoding.ASCII.GetBytes(strKey)); 
		} 
		/// <summary> 
		/// Takes a supplied byte array Key and determines if Key is legal for 
		/// the specified symmetric algorithm. If the hash algorithm has been designated, 
		/// the Key will be hashed before it is checked for validity. 
		/// Returns the byte array of the legal key. 
		/// </summary> 
		private byte[] GetLegalKey(byte[] arrKey) { 
			byte[] bTemp, bHash; 
			char cPadChar = ' '; 

			// first determine if we are to hash the key or not 
			switch(_hashId) { 
				case HashAlgorithm.HashAlgorithmMd5: 
					MD5CryptoServiceProvider hashMd5 = new MD5CryptoServiceProvider(); 
					bHash = hashMd5.ComputeHash(arrKey); 
					// now use the hash as our key 
					arrKey = bHash; 
					break; 

				case HashAlgorithm.HashAlgorithmSha1: 
					SHA1CryptoServiceProvider hashSha1 = new SHA1CryptoServiceProvider(); 
					bHash = hashSha1.ComputeHash(arrKey); 
					// now use the hash as our key 
					arrKey = bHash; 
					break; 

				case HashAlgorithm.HashAlgorithmSha256: 
					SHA256 hashSha256 = new SHA256Managed(); 
					bHash = hashSha256.ComputeHash(arrKey); 
					// now use the hash as our key 
					arrKey = bHash; 
					break; 

				case HashAlgorithm.HashAlgorithmSha384: 
					SHA384 hashSha384 = new SHA384Managed(); 
					bHash = hashSha384.ComputeHash(arrKey); 
					// now use the hash as our key 
					arrKey = bHash; 
					break; 

				case HashAlgorithm.HashAlgorithmSha512: 
					SHA512 hashSha512 = new SHA512Managed(); 
					bHash = hashSha512.ComputeHash(arrKey); 
					// now use the hash as our key 
					arrKey = bHash; 
					break; 
			} 

			if (_objCryptoService.LegalKeySizes.Length > 0) { 
				int minSize = _objCryptoService.LegalKeySizes[0].MinSize; 
				int maxSize = _objCryptoService.LegalKeySizes[0].MaxSize; 

				// key sizes are in bits 
				// if the key size is too small, pad the right with spaces 
				if ((arrKey.Length * 8) < minSize) { 
					bTemp = new byte[minSize / 8]; 

					// first grab everything from the supplied key 
					arrKey.CopyTo(bTemp, 0); 

					// now add spaces to the key 
					for (int i = arrKey.Length; i < (minSize / 8); i++) 
						bTemp[i] = Convert.ToByte(cPadChar); 

				} else 
					// if the key is too large, shorten it to fit 
					if ((arrKey.Length *8) > maxSize) { 
					bTemp = new byte[maxSize / 8]; 

					// now grab everything up to the cutoff point 
					for (int j = 0; j < bTemp.Length; j++) 
						bTemp[j] = arrKey[j]; 

				} else { 
					int iByteCount = arrKey.Length; 
					while(!_objCryptoService.ValidKeySize(iByteCount * 8)) 
						iByteCount++; 

					// now create a new byte array of size iByteCount 
					bTemp = new byte[iByteCount]; 
					// grab everything we can from the supplied key 
					arrKey.CopyTo(bTemp, 0); 
					// now add spaces to the key 
					for (int k = arrKey.Length; k < bTemp.Length; k++) 
						bTemp[k] = Convert.ToByte(cPadChar); 
				} 
			} else { 
				throw new CryptographicException("A Symmetric Algorithm must be selected in order to perform this operation."); 
			} 

			// return the byte array 
			return bTemp; 
		} 

		/// <summary> 
		/// Wrapper method to allow a string to be passed in to determine 
		/// if IV is valid for the specified symmetric algorithm. 
		/// Returns the byte array of the valid IV. 
		/// </summary> 
		private byte[] GetValidIV(string strIv) { 
			// return the byte array 
			return GetValidIV(Encoding.ASCII.GetBytes(strIv)); 
		} 
		/// <summary> 
		/// Takes a supplied byte array IV and determines if IV is valid for 
		/// the specified symmetric algorithm. 
		/// Returns the byte array of the valid IV. 
		/// </summary> 
		private byte[] GetValidIV(byte[] arrIV) { 
			byte[] bTemp = new byte[1]; 
			char cPadChar = ' '; 
			int i; 
			switch(_algorithmId) { 
				case CryptoAlgorithm.CryptoAlgorithmDes: 
				case CryptoAlgorithm.CryptoAlgorithmRc2: 
				case CryptoAlgorithm.CryptoAlgorithmTripleDes: 
					// use 64 bit IV for DES, RC2 and TripleDES 
					bTemp = new byte[8]; 
					break; 

				case CryptoAlgorithm.CryptoAlgorithmRijndael: 
					// use 128 bit IV for Rijndael 
					bTemp = new byte[16]; 
					break; 
			} 

			// if IV has more bytes than we need, just grab as many as we can fit in bTemp 
			// otherwise, grab them all, and pad out the remaining spots with spaces 
			if (arrIV.Length >= bTemp.Length) { 
				for (i = 0; i < bTemp.Length; i++) 
					bTemp[i] = arrIV[i]; 
			} else { 
				// grab what we have 
				arrIV.CopyTo(bTemp, 0); 
				// now fill the rest with spaces 
				for (i = arrIV.Length; i < bTemp.Length; i++) 
					bTemp[i] = Convert.ToByte(cPadChar); 
			} 

			// return byte array 
			return bTemp; 
		} 
		#endregion 

		#region String Encryption/Decryption 
		#region String Encryption Methods 
		/// <summary> 
		/// Encrypts the supplied string and returns the ciphertext. 
		/// The CryptoSymmetric object must have its key and initialization vector defined. 
		/// Encrypts the supplied bytes and returns the ciphertext. 
		/// The CryptoSymmetric object will encrypt using the supplied Key for the key and initialization vector. 
		/// </summary> 
        public byte[] EncryptBytes(byte[] arrInput, byte[] arrKey) { 
			// set the supplied key as the encryption key 
			_arrKey = GetLegalKey(arrKey); 

			// set the IV using the supplied Key 
			_arrIv = GetValidIV(arrKey); 

			return EncryptBytes(arrInput); 
		}
		/// <summary> 
		/// Encrypts the supplied bytes and returns the ciphertext. 
		/// The CryptoSymmetric object will encrypt using the supplied Key and IV. 
		/// </summary> 
        public byte[] EncryptBytes(byte[] arrInput, byte[] arrKey, byte[] arrIv) { 
			// set the supplied key as the encryption key 
			_arrKey = GetLegalKey(arrKey); 

			// set the IV 
			_arrIv = GetValidIV(arrIv); 

			return EncryptBytes(arrInput); 
		} 
		/// <summary> 
		/// The main EncryptString function. The function creates a MemoryStream, a CryptoStream 
		/// and obtains an ICryptoTransform interface. The CryptoStream then 
		/// uses the supplied source string and writes out the encrypted 
		/// text to the MemoryStream using the ICryptoTransform interface. 
		/// </summary> 
        private byte[] EncryptBytes(byte[] arrInput) { 
			// create a MemoryStream so that the process can be done without I/O files 
			MemoryStream objMs = new MemoryStream(); 

			// create an Encryptor 
			ICryptoTransform encrypto = CreateServiceProvider(CryptoMethod.CryptoMethodEncrypt); 

			// create Crypto Stream that transforms a stream using the encryption 
			CryptoStream objCs = new CryptoStream(objMs, encrypto, CryptoStreamMode.Write); 

			// write out encrypted content into MemoryStream 
			objCs.Write(arrInput, 0, arrInput.Length); 
			objCs.FlushFinalBlock(); 

			// get the output 
			byte[] arrOutput = objMs.ToArray(); 

			// close our streams 
			objCs.Close(); 
			objMs.Close(); 

			return arrOutput; 
		} 
		#endregion 

		#region String Decryption Methods 
		/// <summary> 
		/// Decrypts the supplied string and returns the plaintext. 
		/// The CryptoSymmetric object must have its key and initialization vector defined. 
		/// Decrypts the supplied string and returns the plaintext. 
		/// The CryptoSymmetric object will decrypt using the supplied Key for the key and initialization vector. 
		/// </summary> 
        public byte[] DecryptBytes(byte[] arrSource, byte[] arrKey) { 
			// set the supplied key as the encryption key 
			_arrKey = GetLegalKey(arrKey); 

			// set the IV using the supplied Key 
			_arrIv = GetValidIV(arrKey); 

			return DecryptBytes(arrSource); 
		} 
		/// <summary> 
		/// Decrypts the supplied string and returns the plaintext. 
		/// The CryptoSymmetric object will decrypt using the supplied Key and IV. 
		/// </summary> 
        public byte[] DecryptBytes(byte[] arrSource, byte[] arrKey, byte[] arrIV) { 
			// set the supplied key as the encryption key 
			_arrKey = GetLegalKey(arrKey); 

			// set the IV 
			_arrIv = GetValidIV(arrIV); 

			return DecryptBytes(arrSource); 
		} 

        private byte[] DecryptBytes(byte[] arrInput) { 
			// create a MemoryStream with the input 
			MemoryStream objMs = new MemoryStream(arrInput, 0, arrInput.Length); 

			// create a Decryptor 
			ICryptoTransform decrypto = CreateServiceProvider(CryptoMethod.CryptoMethodDecrypt); 

			// create Crypto Stream that transforms the stream using the decryption 
			CryptoStream objCs = new CryptoStream(objMs, decrypto, CryptoStreamMode.Read); 

			// allocate the buffer long enough to hold ciphertext (plaintext is never longer than ciphertext) 
			var arrOutput = new byte[arrInput.Length]; 

			// Start decrypting. 
			int intDecryptedByteCount = objCs.Read(arrOutput, 0, arrOutput.Length); 

			// Close both streams. 
			objCs.Close(); 
			objMs.Close();

            if (intDecryptedByteCount == arrInput.Length) return arrOutput;

            var arrOutput2 = new byte[intDecryptedByteCount];
            for (var i = 0; i < intDecryptedByteCount; ++i)
            {
                arrOutput2[i] = arrOutput[i];
            }
            return arrOutput2;
        } 
		#endregion 
		#endregion 
	}
}