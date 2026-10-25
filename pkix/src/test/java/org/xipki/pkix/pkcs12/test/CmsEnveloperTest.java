// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12.test;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.pkix.asn1.cms.ContentInfo;
import org.xipki.pkix.asn1.cms.EnvelopedData;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.oid.AlgorithmOIDs;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.Hex;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.HashAlgo;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsRecipient;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.pkcs12.Pkcs12KeyStore;
import org.xipki.pkix.util.KeyUtil;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;

/**
 * CMS EnvelopedData test class.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsEnveloperTest {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  @BeforeClass
  public static void init() {
  }

  @Test
  public void testPassword() throws Exception {
    passwordTest(CmsAlgorithm.AES256_CBC,
        AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256),
        "my password".toCharArray());
  }

  @Test
  public void testEeKeyAgree() throws Exception {
    char[] password = "1234".toCharArray();

    Pkcs12KeyStore ks;
    try (InputStream is = Files.newInputStream(
        Paths.get("src/test/resources/pkcs12test/test-ec.p12"))) {
      ks = KeyUtil.loadPKCS12KeyStore(is, password);
    }

    Certificate reciCert = ks.getCertificate("main");
    Asn1Oid curve = reciCert.getSubjectPublicKeyInfo().getAlgorithm().getParameters().asOid();

    PrivateKey reciPrivKey = KeyInfoUtil.getPrivateKey(ks.getKey("main"));

    byte[] data = Hex.decode("1234567890abcdef");

    KeyPairGenerator kpGen = cryptoApi.newKeyPairGenerator("EC");
    kpGen.initialize(new ECGenParameterSpec(curve.getId()));
    KeyPair kp = kpGen.generateKeyPair();

    CmsEnvelopedData ed = new CmsEnvelopedData.Builder()
        .addKeyAgreeRecipient(reciCert, CmsAlgorithm.ECDH_SHA256KDF, CmsAlgorithm.AES128_WRAP, kp)
        .build(CmsAlgorithm.AES128_GCM, data);

    CmsRecipient recipient = new CmsEnvelopedData(ed.getEncoded()).getRecipient(reciCert);
    Assert.assertNotNull(recipient);
    Assert.assertArrayEquals(data, recipient.decrypt(reciPrivKey));
  }

  @Test
  public void testRsaOaep() throws Exception {
    HashAlgo hashAlgo = HashAlgo.SHA256;
    Pkcs12KeyStore ks;
    char[] password = "CHANGEIT".toCharArray();
    try (InputStream is = Files.newInputStream(
        Paths.get("src/test/resources/pkcs12test/test1-enc.p12"))) {
      ks = KeyUtil.loadPKCS12KeyStore(is, password);
    }

    Certificate reciCert = ks.getCertificate("main");
    PrivateKey reciKey = KeyInfoUtil.getPrivateKey(ks.getKey("main"));

    byte[] data = Hex.decode("1234567890abcdef");

    RSAESOAEPParams rsaOaepParams = new RSAESOAEPParams(hashAlgo.algorithmIdentifier(),
        RSAESOAEPParams.DEFAULT_MASK_GEN_FUNCTION, RSAESOAEPParams.DEFAULT_P_SOURCE_ALGORITHM);

    AlgorithmIdentifier oaepAlgId = AlgorithmIdentifier.build(
        AlgorithmOIDs.id_RSAES_OAEP, rsaOaepParams);

    CmsEnvelopedData ed = new CmsEnvelopedData.Builder()
        .addKeyTransRecipient(reciCert, oaepAlgId).build(CmsAlgorithm.AES128_GCM, data);

    CmsRecipient recipient = ed.getRecipients().get(0);
    Assert.assertArrayEquals(data, recipient.decrypt(reciKey));
  }

  private void passwordTest(Asn1Oid algorithm, AlgorithmIdentifier prf, char[] password)
      throws Exception {
    byte[] data = Hex.decode("1234567890abcdef");
    byte[] salt = new byte[20];
    int iterationCount = 10000;

    CmsEnvelopedData ed0 = new CmsEnvelopedData.Builder()
        .addPasswordRecipient(password, algorithm, prf, salt, iterationCount)
        .build(CmsAlgorithm.AES128_CBC, data);

    EnvelopedData ed1 = EnvelopedData.fromAsn1(ed0.toASN1Structure().getContent().asSequence());
    ContentInfo ci = ContentInfo.build(CmsOIDs.envelopedData, ed1);
    CmsEnvelopedData ed = new CmsEnvelopedData(ci);

    CmsRecipient recipient = ed.getRecipients().get(0);
    Assert.assertEquals(CmsRecipient.Type.PASSWORD, recipient.getType());
    Assert.assertArrayEquals(data, recipient.decrypt(password));
  }

}
