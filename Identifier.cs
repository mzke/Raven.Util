//https://ravendb.net/articles/avoiding-exposing-identifier-details-to-your-users
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Mzke.Raven.Util
{
    public  class Identifier
    {
        public CryptoId CryptoId {get;}
        public string Id { get;  }

        public Identifier(string id)
        {
            Id = id;
            CryptoId.Value = Encrypt(id);
        }

        public Identifier(CryptoId encryptedId)
        {
            CryptoId = encryptedId;
            Id = Decrypt(CryptoId.Value);
        }

        public  string Simple()
        {
            return Simple(Id);
        }

        public static string Simple(string id)
        {
            try
            {
                var result = id.ToString().Split("/");
                return result[1];
            }
            catch
            {
                return id;
            }
        }

        public static string Decrypt(string hidden) 
        { 
            return Decrypt(hidden, InternalKey());
        }

        public static string Decrypt(string hidden, byte[] key)
        {
            Span<byte> data = SimpleBase.Base58.Bitcoin.Decode(hidden);
            byte[] nonce = data.Slice(0, 12).ToArray();
            byte[] encrypted = data.Slice(12).ToArray();
            byte[] plain = Sodium.SecretAeadAes.Decrypt(encrypted, nonce, key);
            return Encoding.UTF8.GetString(plain);
        }

        public  string Encrypt()
        {
            return Encrypt(Id, InternalKey());
        }

        public static string Encrypt(string id)
        {
            return Encrypt(id, InternalKey());
        }
        
        public static string Encrypt(string id, byte[] key)
        {
            byte[] nonce = Sodium.SecretAeadAes.GenerateNonce();
            byte[] encrypted = Sodium.SecretAeadAes.Encrypt(Encoding.UTF8.GetBytes(id), nonce, InternalKey());
            return SimpleBase.Base58.Bitcoin.Encode(nonce.Concat(encrypted).ToArray());
        }

        private static byte[] InternalKey()
        {
            return new byte[] 
            {
                0x02, 0x03, 0x05, 0x07, 0x11, 0x13, 0x17, 0x19,
                0x23, 0x29, 0x31, 0x37, 0x41, 0x43, 0x47, 0x53,
                0x59, 0x61, 0x67, 0x71, 0x73, 0x79, 0x83, 0x89,
                0x97, 0x02, 0x03, 0x05, 0x07, 0x11, 0x13, 0x17
            };
        }
    }
}
