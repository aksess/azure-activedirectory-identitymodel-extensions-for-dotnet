//-----------------------------------------------------------------------
// Copyright (c) Microsoft Open Technologies, Inc.
// All Rights Reserved
// Apache License 2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
// http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-----------------------------------------------------------------------

using Microsoft.IdentityModel.Protocols;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IdentityModel.Test;
using System.IdentityModel.Tokens;

namespace Microsoft.IdentityModel.Test
{
    /// <summary>
    /// 
    /// </summary>
    [TestClass]
    public class OpenIdConnectMetadataTests
    {
        public TestContext TestContext { get; set; }

        [ClassInitialize]
        public static void ClassSetup(TestContext testContext)
        {
        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
        }

        [TestInitialize]
        public void Initialize()
        {
        }

        [TestMethod]
        [TestProperty("TestCaseID", "3452b8a7-fae1-4b20-b78b-03f90c39ee81")]
        [Description("Tests: Constructors")]
        public void OpenIdConnectMetadata_Constructors()
        {
            RunOpenIdConnectMetadataTest((string)null, new OpenIdConnectMetadata(), ExpectedException.NoExceptionExpected);
            RunOpenIdConnectMetadataTest((IDictionary<string, object>)null, new OpenIdConnectMetadata(), ExpectedException.NoExceptionExpected);
            RunOpenIdConnectMetadataTest(SharedData.OpenIdConnectMetadataString, SharedData.OpenIdConnectMetatdata1, ExpectedException.NoExceptionExpected);
        }

        private OpenIdConnectMetadata RunOpenIdConnectMetadataTest(object obj, OpenIdConnectMetadata compareTo, ExpectedException expectedException, bool asString = true)
        {
            OpenIdConnectMetadata openIdConnectMetadata = null;
            try
            {
                if (obj is string)
                {
                    openIdConnectMetadata = new OpenIdConnectMetadata(obj as string);
                }
                else if (obj is IDictionary<string, object>)
                {
                    openIdConnectMetadata = new OpenIdConnectMetadata(obj as IDictionary<string, object>);
                }
                else
                {
                    if (asString)
                    {
                        openIdConnectMetadata = new OpenIdConnectMetadata(obj as string);
                    }
                    else
                    {
                        openIdConnectMetadata = new OpenIdConnectMetadata(obj as IDictionary<string, object>);
                    }
                }
                expectedException.ProcessNoException();
            }
            catch (Exception ex)
            {
                expectedException.ProcessException(ex);
            }

            if (compareTo != null)
            {
                Assert.IsTrue(IdentityComparer.AreEqual(openIdConnectMetadata, compareTo), "jsonWebKey created from: " + (obj == null ? "NULL" : obj.ToString() + " did not match expected."));
            }

            return openIdConnectMetadata;
        }

        [TestMethod]
        [TestProperty("TestCaseID", "60d42142-5fbe-4bbc-aefa-9b18de426cbc")]
        [Description("Tests: Defaults")]
        public void OpenIdConnectMetadata_Defaults()
        {
            OpenIdConnectMetadata metadata = new OpenIdConnectMetadata();
            Assert.IsNull(metadata.Authorization_Endpoint);
            Assert.IsNull(metadata.End_Session_Endpoint);
            Assert.IsNull(metadata.Issuer);
            Assert.IsNull(metadata.Jwks_Uri);
            Assert.IsNull(metadata.Token_Endpoint);
            Assert.IsNotNull(metadata.SigningTokens);
        }

        [TestMethod]
        [TestProperty("TestCaseID", "55312093-0e2d-4ca2-bb20-9bf125856ea3")]
        [Description("Tests: GetSets")]
        public void OpenIdConnectMetadata_GetSets()
        {
            OpenIdConnectMetadata metadata = new OpenIdConnectMetadata();
            TestUtilities.CallAllPublicInstanceAndStaticPropertyGets(metadata, "OpenIdConnectMetadata_GetSets");

            List<string> methods = new List<string> { "Authorization_Endpoint", "End_Session_Endpoint", "Issuer", "Jwks_Uri", "Token_Endpoint" };
            foreach(string method in methods)
            {
                TestUtilities.GetSet(metadata, method, null, new object[] { Guid.NewGuid().ToString(), null, Guid.NewGuid().ToString() });
            }

            string authorization_Endpoint = Guid.NewGuid().ToString();
            string end_Session_Endpoint = Guid.NewGuid().ToString();
            string issuer = Guid.NewGuid().ToString();
            string jwks_Uri = Guid.NewGuid().ToString();
            string token_Endpoint = Guid.NewGuid().ToString();

            metadata = new OpenIdConnectMetadata()
            {
                Authorization_Endpoint = authorization_Endpoint,
                End_Session_Endpoint = end_Session_Endpoint,
                Issuer = issuer,
                Jwks_Uri = jwks_Uri,
                Token_Endpoint = token_Endpoint,
            };

            List<SecurityToken> signingTokens = new List<SecurityToken>{KeyingMaterial.X509Token_1024, KeyingMaterial.X509Token_Public_2048};
            metadata.SigningTokens.Add(KeyingMaterial.X509Token_1024);
            metadata.SigningTokens.Add(KeyingMaterial.X509Token_Public_2048);

            Assert.AreEqual(metadata.Authorization_Endpoint, authorization_Endpoint);
            Assert.AreEqual(metadata.End_Session_Endpoint, end_Session_Endpoint);
            Assert.AreEqual(metadata.Issuer, issuer);
            Assert.AreEqual(metadata.Jwks_Uri, jwks_Uri);
            Assert.AreEqual(metadata.Token_Endpoint, token_Endpoint);
            Assert.IsTrue(IdentityComparer.AreEqual(metadata.SigningTokens, signingTokens));
        }

        [TestMethod]
        [TestProperty("TestCaseID", "43190276-8350-495e-ae4c-50229f0a5dbf")]
        [Description("Tests: Publics")]
        public void OpenIdConnectMetadata_Publics()
        {
        }
    }
}