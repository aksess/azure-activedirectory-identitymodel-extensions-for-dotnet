//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using System;
using System.IO;
using System.Security.Cryptography;
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents an XmlDsig Signature element.
    /// </summary>
    public class Signature
    {
        private string _prefix = XmlSignatureConstants.Prefix;

        // TODO - consider constructor without SignedInfo
        public Signature()
        {
        }

        public Signature(XmlReader reader)
        {
            ReadFrom(reader);
        }

        public string Id { get; set; }

        public KeyInfo KeyInfo { get; set; }

        public string SignatureValue { get; set; }

        public SignedInfo SignedInfo { get; set; }

        internal void ComputeSignature(SigningCredentials credentials)
        {
            var signedInfo = new PreDigestedSignedInfo(XmlSignatureConstants.Algorithms.ExcC14N, credentials.Digest, credentials.Algorithm);
//            var hash = credentials.Key.CryptoProviderFactory.CreateHashAlgorithm(credentials.Digest);
//            SignedInfo.ComputeReferenceDigests();
//            SignatureBytes = SignedInfo.ComputeHashBytes(hash);
        }

        public byte[] SignatureBytes { get; set; }

        private void ReadFrom(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);

            _prefix = reader.Prefix;
            Id = reader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
            reader.Read();

            SignedInfo = new SignedInfo(reader);
            reader.MoveToContent();
            SignatureValue = reader.ReadElementContentAsString().Trim();
            SignatureBytes = System.Convert.FromBase64String(SignatureValue);
            KeyInfo = new KeyInfo(reader);

            // </Signature>
            reader.MoveToContent();
            reader.ReadEndElement();
        }

        public XmlTokenStreamReader TokenSource { get; set; }

        public void Verify(SecurityKey key)
        {
            if (key == null)
                throw LogArgumentNullException(nameof(key));

            var signatureProvider = key.CryptoProviderFactory.CreateForVerifying(key, SignedInfo.SignatureMethod);
            if (signatureProvider == null)
                throw LogExceptionMessage(new XmlValidationException(FormatInvariant(LogMessages.IDX21203, key.CryptoProviderFactory, key, SignedInfo.SignatureMethod)));

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    SignedInfo.GetCanonicalBytes(memoryStream);

                    if (!signatureProvider.Verify(SignedInfo.CanonicalStream.ToArray(), SignatureBytes))
                        throw LogExceptionMessage(new CryptographicException(LogMessages.IDX21200));
                }
            }
            finally
            {
                if (signatureProvider != null)
                    key.CryptoProviderFactory.ReleaseSignatureProvider(signatureProvider);
            }

            if (!SignedInfo.Reference.Verify(key.CryptoProviderFactory, TokenSource))
                throw LogExceptionMessage(new CryptographicException(FormatInvariant(LogMessages.IDX21201, SignedInfo.Reference.Uri)));
        }

        public virtual void WriteTo(XmlWriter writer, SigningCredentials credentials)
        {
            if (writer == null)
                LogArgumentNullException(nameof(writer));

            if (credentials == null)
                LogArgumentNullException(nameof(credentials));


            // <Signature>
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace);
            if (Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);

            SignedInfo.WriteTo(writer);
            var memoryStream = new MemoryStream();
            var factory = credentials.CryptoProviderFactory ?? credentials.Key.CryptoProviderFactory;
            SignedInfo.GetCanonicalBytes(memoryStream);
            SignatureBytes = (factory.CreateForSigning(credentials.Key, credentials.Algorithm)).Sign(memoryStream.ToArray());
            SignatureValue = Convert.ToBase64String(SignatureBytes);

            // <SignatureValue>
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.SignatureValue, XmlSignatureConstants.Namespace);

            // @Id
            if (Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);

            writer.WriteString(SignatureValue);

            // </ SignatureValue>
            writer.WriteEndElement();

            // <KeyInfo>
            KeyInfo = new KeyInfo(credentials.Key);
            KeyInfo.WriteTo(writer);

            // </ Signature>
            writer.WriteEndElement();
        }
    }
}
