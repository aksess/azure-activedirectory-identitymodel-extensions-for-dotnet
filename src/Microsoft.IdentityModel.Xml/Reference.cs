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
using System.Xml;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    /// <summary>
    /// Represents the &lt;Reference> element in a &lt;SignedInfo> clause.
    /// </summary>
    public class Reference
    {
        public Reference()
        {
        }

        public Reference(XmlReader reader)
        {
            ReadFrom(reader);
        }

        public Reference(params Transform[] transforms)
        {
            if (transforms == null)
                LogArgumentNullException(nameof(transforms));

            TransformChain = new TransformChain(transforms);
        }

        public string DigestMethod { get; set; }

        public string  DigestValue { get; set; }

        public byte[]  DigestBytes { get; set; }

        public string Id { get; set; }

        public string Prefix { get; set; } = XmlSignatureConstants.Prefix;

        internal TransformChain TransformChain { get; }  = new TransformChain();

        public string Type { get; set; }

        public string Uri { get; set; }

        public bool Verified { get; set; }

        internal bool Verify(CryptoProviderFactory cryptoProviderFactory, XmlTokenStreamReader tokenStream)
        {
            Verified = Utility.AreEqual(ComputeDigest(cryptoProviderFactory, tokenStream), DigestBytes);
            return Verified;
        }

        /// <summary>
        /// We look at the URI reference to decide if we should preserve comments while canonicalization.
        /// Only when the reference is xpointer(/) or xpointer(id(SomeId)) do we preserve comments during canonicalization 
        /// of the reference element for computing the digest.
        /// </summary>
        /// <param name="uri">The Uri reference </param>
        /// <returns>true if comments should be preserved.</returns>
        private static bool ShouldPreserveComments(string uri)
        {
            bool preserveComments = false;

            if (!string.IsNullOrEmpty(uri))
            {
                //removes the hash
                string idref = uri.Substring(1);

                if (idref == "xpointer(/)")
                {
                    preserveComments = true;
                }
                else if (idref.StartsWith("xpointer(id(", StringComparison.Ordinal) && (idref.IndexOf(")", StringComparison.Ordinal) > 0))
                {
                    // Dealing with XPointer of type #xpointer(id("ID")). Other XPointer support isn't handled here and is anyway optional 
                    preserveComments = true;
                }
            }

            return preserveComments;
        }

        // TODO - hook this up to write
        internal void ComputeAndSetDigest()
        {
            //_digestValueElement.Value = ComputeDigest();
        }

        //public byte[] ComputeDigest()
        //{
        //    if (TransformChain.TransformCount == 0)
        //        throw LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));

        //    if (_resolvedXmlSource == null)
        //        throw LogExceptionMessage(new CryptographicException("UnableToResolveReferenceUriForSignature, this.uri"));

        //    return TransformChain.TransformToDigest(_resolvedXmlSource, DigestAlgorithm);
        //}

        private byte[] ComputeDigest(CryptoProviderFactory providerFactory, XmlTokenStreamReader tokenStream)
        {
            if (tokenStream == null)
                throw LogArgumentNullException(nameof(tokenStream));

            if (TransformChain.Count == 0)
                throw LogExceptionMessage(new NotSupportedException("EmptyTransformChainNotSupported"));

            var hashAlg = providerFactory.CreateHashAlgorithm(DigestMethod);
            try
            {
                return TransformChain.TransformToDigest(tokenStream, hashAlg);
            }
            finally
            {
                if (hashAlg != null)
                    providerFactory.ReleaseHashAlgorithm(hashAlg);
            }
        }

        public void ReadFrom(XmlReader reader)
        {
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);

            Prefix = reader.Prefix;
            Id = reader.GetAttribute(XmlSignatureConstants.Attributes.Id, null);
            Uri = reader.GetAttribute(XmlSignatureConstants.Attributes.URI, null);
            Type = reader.GetAttribute(XmlSignatureConstants.Attributes.Type, null);

            reader.Read();

            if (reader.IsStartElement(XmlSignatureConstants.Elements.Transforms, XmlSignatureConstants.Namespace))
                TransformChain.ReadFrom(reader, ShouldPreserveComments(Uri));
            else
                throw XmlUtil.LogReadException(LogMessages.IDX21011, XmlSignatureConstants.Namespace, XmlSignatureConstants.Elements.Transforms, reader.NamespaceURI, reader.LocalName);


            // <DigestMethod>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
            bool isEmptyElement = reader.IsEmptyElement;
            DigestMethod = reader.GetAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            if (string.IsNullOrEmpty(DigestMethod))
                throw XmlUtil.OnRequiredAttributeMissing(XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Attributes.Algorithm);

            reader.Read();
            reader.MoveToContent();
            if (!isEmptyElement)
            {
                reader.MoveToContent();
                reader.ReadEndElement();
            }

            // <DigestValue>
            XmlUtil.CheckReaderOnEntry(reader, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
            DigestValue = reader.ReadElementContentAsString().Trim();
            if (string.IsNullOrEmpty(DigestValue))
                throw XmlUtil.LogReadException(LogMessages.IDX21206, Id);

            DigestBytes = System.Convert.FromBase64String(DigestValue);

            // </Reference>
            reader.MoveToContent();
            reader.ReadEndElement();
        }

        public void WriteTo(XmlWriter writer)
        {
            writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.Reference, XmlSignatureConstants.Namespace);
            if (Id != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Id, null, Id);

            if (Uri != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.URI, null, Uri);

            if (Type != null)
                writer.WriteAttributeString(XmlSignatureConstants.Attributes.Type, null, Type);

            if (TransformChain.Count > 0)
                TransformChain.WriteTo(writer);

            // <DigestMethod>
            writer.WriteStartElement(Prefix, XmlSignatureConstants.Elements.DigestMethod, XmlSignatureConstants.Namespace);
            writer.WriteStartAttribute(XmlSignatureConstants.Attributes.Algorithm, null);
            writer.WriteString(DigestMethod);
            writer.WriteEndAttribute();

            // </DigestMethod>
            writer.WriteEndElement();

            // <DigestValue>
            writer.WriteStartElement(XmlSignatureConstants.Prefix, XmlSignatureConstants.Elements.DigestValue, XmlSignatureConstants.Namespace);
            if (DigestValue != null)
                writer.WriteString(DigestValue);

            else if (DigestBytes != null)
                writer.WriteBase64(DigestBytes, 0, DigestBytes.Length);

            // </DigestValue>
            writer.WriteEndElement();

            // </Reference>
            writer.WriteEndElement();
        }
    }
}