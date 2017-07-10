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
using System.Security.Cryptography;
using System.Xml;
using static Microsoft.IdentityModel.Logging.LogHelper;

namespace Microsoft.IdentityModel.Xml
{
    public sealed class EnvelopedSignatureTransform : Transform
    {
        private string _prefix = XmlSignatureConstants.Prefix;

        public EnvelopedSignatureTransform()
        {
            Algorithm = XmlSignatureConstants.Algorithms.EnvelopedSignature;
        }

        public override object Process(XmlTokenStreamReader reader)
        {
            if (reader == null)
                LogArgumentNullException(nameof(reader));

            // The Enveloped Signature Transform removes the Signature element from the canonicalized octets
            // Specifying '1' as the depth, we narrow our range of support so that we require
            // the signature be a direct child of the element being signed.
            reader.XmlTokens.SetElementExclusion(XmlSignatureConstants.Elements.Signature, XmlSignatureConstants.Namespace, 1);
            return reader;
        }

        // this transform is not allowed as the last one in a chain
        public override byte[] ProcessAndDigest(XmlTokenStreamReader reader, HashAlgorithm hash)
        {
            throw LogExceptionMessage(new NotSupportedException("UnsupportedLastTransform"));
        }

        public override void ReadFrom(XmlReader reader, bool preserveComments)
        {
            reader.MoveToContent();
            string algorithm = XmlUtil.ReadEmptyElementAndRequiredAttribute(reader,
                XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace, XmlSignatureConstants.Attributes.Algorithm, out _prefix);

            if (algorithm != Algorithm)
                throw LogExceptionMessage(new CryptographicException("AlgorithmMismatchForTransform"));
        }

        public override void WriteTo(XmlWriter writer)
        {
            writer.WriteStartElement(_prefix, XmlSignatureConstants.Elements.Transform, XmlSignatureConstants.Namespace);
            writer.WriteAttributeString(XmlSignatureConstants.Attributes.Algorithm, null, Algorithm);
            writer.WriteEndElement();
        }
    }
}
