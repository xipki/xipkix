// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert.test;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcePasswordEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper;
import org.junit.Assert;
import org.junit.Test;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1PrintableString;
import org.xipki.pkix.asn1.cms.Attributes;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.RSAESOAEPParams;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.asn1.oid.NistOIDs;
import org.xipki.codec.asn1.oid.OiwOIDs;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.cms.CmsAlgorithm;
import org.xipki.pkix.cms.CmsEnvelopedData;
import org.xipki.pkix.cms.CmsException;
import org.xipki.pkix.cms.CmsRecipient;
import org.xipki.pkix.cms.CmsSignedData;
import org.xipki.pkix.cms.CmsSigner;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.spec.MGF1ParameterSpec;
import java.util.List;

/**
 * Interoperability tests of the CMS SignedData and EnvelopedData against BouncyCastle, in both
 * directions.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsInteropTest {

  private static final byte[] DATA = "Hello CMS, test data for interoperability"
      .getBytes(StandardCharsets.UTF_8);

  private static final char[] PASSWORD = "my password".toCharArray();

  // ---------------- SignedData: xipki -> BouncyCastle ----------------

  @Test
  public void testSignedDataRsaSha256() throws Exception {
    signedDataXipkiToBc(TestUtil.rsa(), "SHA256withRSA",
        AlgorithmIdentifier.ofNullParams(PkcsOIDs.sha256WithRSAEncryption),
        AlgorithmIdentifier.ofNullParams(NistOIDs.id_sha256));
  }

  @Test
  public void testSignedDataRsaSha1() throws Exception {
    // SHA1withRSA is written as rsaEncryption in the SignerInfo, as SCEP GetNextCACert does.
    CMSSignedData bcSd = signedDataXipkiToBc(TestUtil.rsa(), "SHA1withRSA",
        AlgorithmIdentifier.ofNullParams(PkcsOIDs.sha1WithRSAEncryption),
        AlgorithmIdentifier.ofNullParams(OiwOIDs.idSHA1));
    SignerInformation si = bcSd.getSignerInfos().getSigners().iterator().next();
    Assert.assertEquals(PkcsOIDs.rsaEncryption.getId(), si.getEncryptionAlgOID());
  }

  @Test
  public void testSignedDataEcdsa() throws Exception {
    signedDataXipkiToBc(TestUtil.ec(), "SHA256withECDSA",
        new AlgorithmIdentifier(new Asn1Oid("1.2.840.10045.4.3.2")),
        AlgorithmIdentifier.ofNullParams(NistOIDs.id_sha256));
  }

  private CMSSignedData signedDataXipkiToBc(
      TestUtil.KeyAndCert kc, String jceAlg, AlgorithmIdentifier sigAlgId,
      AlgorithmIdentifier digestAlgId) throws Exception {
    Attributes signedAttrs = new Attributes(Attribute.createNoParse(
        new Asn1Oid("2.16.840.1.113733.1.9.7"), new Asn1PrintableString("tid-1234")));

    CmsSignedData sd = new CmsSignedData.Builder()
        .setContent(CmsOIDs.data, DATA, true)
        .addCertificate(kc.cert)
        .addSigner(TestUtil.signer(kc.keyPair.getPrivate(), jceAlg, sigAlgId), kc.cert,
            digestAlgId, signedAttrs, null)
        .build();

    // BouncyCastle verifies
    CMSSignedData bcSd = new CMSSignedData(sd.getEncoded());
    Assert.assertArrayEquals("content", DATA, (byte[]) bcSd.getSignedContent().getContent());
    Assert.assertEquals("keycerts", 1, bcSd.getCertificates().getMatches(null).size());
    SignerInformation si = bcSd.getSignerInfos().getSigners().iterator().next();
    Assert.assertTrue("BC verify", si.verify(new JcaSimpleSignerInfoVerifierBuilder()
        .setProvider(TestUtil.BC).build(kc.bcCert)));
    Assert.assertNotNull("signed attribute",
        si.getSignedAttributes().get(new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.7")));

    // xipki verifies its own SignedData
    CmsSigner signer = new CmsSignedData(sd.getEncoded()).getSigners().get(0);
    Assert.assertTrue(signer.matches(kc.cert));
    Assert.assertTrue("xipki verify", signer.verify(
        TestUtil.verifierProvider(kc.keyPair.getPublic(), kc.cert)));
    return bcSd;
  }

  // ---------------- SignedData: BouncyCastle -> xipki ----------------

  @Test
  public void testSignedDataFromBc() throws Exception {
    for (TestUtil.KeyAndCert kc : List.of(TestUtil.rsa(), TestUtil.ec())) {
      for (String hash : new String[]{"SHA1", "SHA256", "SHA384"}) {
        String alg = hash + "with" + (kc == TestUtil.ec() ? "ECDSA" : "RSA");

        AttributeTable attrs = new AttributeTable(new org.bouncycastle.asn1.cms.Attribute(
            new ASN1ObjectIdentifier("2.16.840.1.113733.1.9.7"),
            new DERSet(new DERPrintableString("tid-1234"))));

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(TestUtil.BC).build())
            .setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(attrs))
            .build(new JcaContentSignerBuilder(alg).setProvider(TestUtil.BC)
                .build(kc.keyPair.getPrivate()), kc.bcCert));
        gen.addCertificates(new JcaCertStore(List.of(kc.bcCert)));
        byte[] encoded = gen.generate(new CMSProcessableByteArray(DATA), true).getEncoded();

        CmsSignedData sd = new CmsSignedData(encoded);
        Assert.assertEquals(alg + ": content type", CmsOIDs.data, sd.getContentType());
        Assert.assertArrayEquals(alg + ": content", DATA, sd.getContent());
        Assert.assertEquals(alg + ": certificates", 1, sd.getCertificates().size());

        CmsSigner signer = sd.getSigners().get(0);
        Assert.assertTrue(alg + ": matches", signer.matches(sd.getCertificates().get(0)));
        Assert.assertNotNull(alg + ": signed attribute", signer.getSignedAttributes()
            .getFirstAttribute(new Asn1Oid("2.16.840.1.113733.1.9.7")));
        Assert.assertTrue(alg + ": verify", signer.verify(
            TestUtil.verifierProvider(kc.keyPair.getPublic(), kc.cert)));

        // wrong key
        TestUtil.KeyAndCert other = (kc == TestUtil.ec()) ? TestUtil.rsa() : TestUtil.ec();
        boolean valid;
        try {
          valid = signer.verify(TestUtil.verifierProvider(other.keyPair.getPublic(), null));
        } catch (Exception e) {
          valid = false;
        }
        Assert.assertFalse(alg + ": verify with wrong key", valid);
      }
    }
  }

  @Test
  public void testSignedDataTamperedContent() throws Exception {
    TestUtil.KeyAndCert kc = TestUtil.rsa();
    CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
    gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
        new JcaDigestCalculatorProviderBuilder().setProvider(TestUtil.BC).build())
        .build(new JcaContentSignerBuilder("SHA256withRSA").setProvider(TestUtil.BC)
            .build(kc.keyPair.getPrivate()), kc.bcCert));
    byte[] encoded = gen.generate(new CMSProcessableByteArray(DATA), true).getEncoded();

    // flip one byte of the content
    int idx = indexOf(encoded, DATA);
    encoded[idx] ^= 1;

    CmsSigner signer = new CmsSignedData(encoded).getSigners().get(0);
    try {
      signer.verify(TestUtil.verifierProvider(kc.keyPair.getPublic(), kc.cert));
      Assert.fail("tampered content must be rejected");
    } catch (CmsException e) {
      Assert.assertTrue(e.getMessage(), e.getMessage().contains("message-digest"));
    }
  }

  @Test
  public void testDegenerateSignedData() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    TestUtil.KeyAndCert ec = TestUtil.ec();
    CmsSignedData sd = new CmsSignedData.Builder()
        .addCertificate(rsa.cert).addCertificate(ec.cert).build();

    CMSSignedData bcSd = new CMSSignedData(sd.getEncoded());
    Assert.assertNull(bcSd.getSignedContent());
    Assert.assertEquals(0, bcSd.getSignerInfos().size());
    Assert.assertEquals(2, bcSd.getCertificates().getMatches(null).size());

    CmsSignedData parsed = new CmsSignedData(sd.getEncoded());
    Assert.assertNull(parsed.getContent());
    Assert.assertEquals(2, parsed.getCertificates().size());
  }

  // ---------------- EnvelopedData: xipki -> BouncyCastle ----------------

  @Test
  public void testEnvelopedDataToBc() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    TestUtil.KeyAndCert ec = TestUtil.ec();
    Asn1Oid[] contentAlgs = {CmsAlgorithm.AES128_CBC, CmsAlgorithm.AES256_CBC,
        CmsAlgorithm.DES_EDE3_CBC, CmsAlgorithm.AES128_GCM, CmsAlgorithm.AES256_GCM};

    for (Asn1Oid contentAlg : contentAlgs) {
      // key transport: RSA PKCS#1 v1.5
      CmsEnvelopedData ed = new CmsEnvelopedData.Builder().addKeyTransRecipient(rsa.cert)
          .build(contentAlg, DATA);
      bcDecryptKeyTrans(contentAlg + ", RSA", ed, rsa);

      // key transport: RSA-OAEP with SHA-256
      AlgorithmIdentifier sha256 = AlgorithmIdentifier.ofNullParams(NistOIDs.id_sha256);
      AlgorithmIdentifier oaep = AlgorithmIdentifier.build(PkcsOIDs.id_RSAES_OAEP,
          new RSAESOAEPParams(sha256, AlgorithmIdentifier.build(PkcsOIDs.id_mgf1, sha256),
              RSAESOAEPParams.DEFAULT_P_SOURCE_ALGORITHM));
      ed = new CmsEnvelopedData.Builder().addKeyTransRecipient(rsa.cert, oaep)
          .build(contentAlg, DATA);
      bcDecryptKeyTrans(contentAlg + ", RSA-OAEP", ed, rsa);

      // key agreement: ECDH-SHA256KDF with AES-256 wrap
      ed = new CmsEnvelopedData.Builder().addKeyAgreeRecipient(ec.cert,
          CmsAlgorithm.ECDH_SHA256KDF, CmsAlgorithm.AES256_WRAP, TestUtil.newEcKeyPair())
          .build(contentAlg, DATA);
      CMSEnvelopedData bcEd = new CMSEnvelopedData(ed.getEncoded());
      KeyAgreeRecipientInformation kari =
          (KeyAgreeRecipientInformation) bcEd.getRecipientInfos().getRecipients().iterator().next();
      Assert.assertArrayEquals(contentAlg + ", ECDH", DATA, kari.getContent(
          new JceKeyAgreeEnvelopedRecipient(ec.keyPair.getPrivate()).setProvider(TestUtil.BC)));

      // password: PBKDF2 with HMAC-SHA256, AES-256-CBC as KEK
      byte[] salt = new byte[16];
      ed = new CmsEnvelopedData.Builder().addPasswordRecipient(PASSWORD, CmsAlgorithm.AES256_CBC,
          AlgorithmIdentifier.ofNullParams(PkcsOIDs.id_hmacWithSHA256), salt, 10000)
          .build(contentAlg, DATA);
      bcEd = new CMSEnvelopedData(ed.getEncoded());
      PasswordRecipientInformation pwri =
          (PasswordRecipientInformation) bcEd.getRecipientInfos().getRecipients().iterator().next();
      Assert.assertArrayEquals(contentAlg + ", password", DATA, pwri.getContent(
          new JcePasswordEnvelopedRecipient(PASSWORD).setProvider(TestUtil.BC)));
    }
  }

  private static void bcDecryptKeyTrans(String desc, CmsEnvelopedData ed, TestUtil.KeyAndCert kc)
      throws Exception {
    CMSEnvelopedData bcEd = new CMSEnvelopedData(ed.getEncoded());
    RecipientInformation ri = bcEd.getRecipientInfos().getRecipients().iterator().next();
    Assert.assertArrayEquals(desc, DATA, ri.getContent(
        new JceKeyTransEnvelopedRecipient(kc.keyPair.getPrivate()).setProvider(TestUtil.BC)));
  }

  // ---------------- EnvelopedData: BouncyCastle -> xipki ----------------

  @Test
  public void testEnvelopedDataFromBc() throws Exception {
    TestUtil.KeyAndCert rsa = TestUtil.rsa();
    TestUtil.KeyAndCert ec = TestUtil.ec();
    ASN1ObjectIdentifier[] contentAlgs = {CMSAlgorithm.AES128_CBC, CMSAlgorithm.AES256_CBC,
        CMSAlgorithm.DES_EDE3_CBC, CMSAlgorithm.AES128_GCM, CMSAlgorithm.AES256_GCM};

    for (ASN1ObjectIdentifier contentAlg : contentAlgs) {
      // key transport: RSA PKCS#1 v1.5 and RSA-OAEP
      for (boolean oaep : new boolean[]{false, true}) {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        if (oaep) {
          OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
              MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
          gen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(rsa.jceCert(),
              new JceAsymmetricKeyWrapper(spec, rsa.keyPair.getPublic())
                  .setProvider(TestUtil.BC)).setProvider(TestUtil.BC));
        } else {
          gen.addRecipientInfoGenerator(
              new JceKeyTransRecipientInfoGenerator(rsa.jceCert()).setProvider(TestUtil.BC));
        }
        byte[] encoded = bcEncrypt(gen, contentAlg);

        CmsEnvelopedData ed = new CmsEnvelopedData(encoded);
        CmsRecipient recipient = ed.getRecipient(rsa.cert);
        Assert.assertNotNull(recipient);
        Assert.assertEquals(CmsRecipient.Type.KEY_TRANS, recipient.getType());
        Assert.assertArrayEquals(contentAlg + ", RSA oaep=" + oaep, DATA,
            recipient.decrypt(rsa.keyPair.getPrivate()));
      }

      // key agreement
      for (ASN1ObjectIdentifier kaAlg : new ASN1ObjectIdentifier[]{
          CMSAlgorithm.ECDH_SHA1KDF, CMSAlgorithm.ECDH_SHA256KDF, CMSAlgorithm.ECDH_SHA384KDF}) {
        KeyPair ephemeral = TestUtil.newEcKeyPair();
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JceKeyAgreeRecipientInfoGenerator(kaAlg,
            ephemeral.getPrivate(), ephemeral.getPublic(), CMSAlgorithm.AES128_WRAP)
            .addRecipient(ec.jceCert()).setProvider(TestUtil.BC));
        byte[] encoded = bcEncrypt(gen, contentAlg);

        CmsRecipient recipient = new CmsEnvelopedData(encoded).getRecipient(ec.cert);
        Assert.assertNotNull(recipient);
        Assert.assertEquals(CmsRecipient.Type.KEY_AGREE, recipient.getType());
        Assert.assertArrayEquals(contentAlg + ", " + kaAlg, DATA,
            recipient.decrypt(ec.keyPair.getPrivate()));
      }

      // password
      for (ASN1ObjectIdentifier kekAlg : new ASN1ObjectIdentifier[]{
          CMSAlgorithm.AES128_CBC, CMSAlgorithm.AES256_CBC, CMSAlgorithm.DES_EDE3_CBC}) {
        CMSEnvelopedDataGenerator gen = new CMSEnvelopedDataGenerator();
        gen.addRecipientInfoGenerator(new JcePasswordRecipientInfoGenerator(kekAlg, PASSWORD)
            .setProvider(TestUtil.BC).setPRF(PasswordRecipient.PRF.HMacSHA256)
            .setSaltAndIterationCount(new byte[20], 2048));
        byte[] encoded = bcEncrypt(gen, contentAlg);

        CmsRecipient recipient = new CmsEnvelopedData(encoded).getRecipients().get(0);
        Assert.assertEquals(CmsRecipient.Type.PASSWORD, recipient.getType());
        Assert.assertArrayEquals(contentAlg + ", password " + kekAlg, DATA,
            recipient.decrypt(PASSWORD));

        try {
          recipient.decrypt("wrong password".toCharArray());
          Assert.fail("wrong password must be rejected");
        } catch (CmsException e) {
          // expected
        }
      }
    }
  }

  @Test
  public void testRecipientNotFound() throws Exception {
    CmsEnvelopedData ed = new CmsEnvelopedData.Builder()
        .addKeyTransRecipient(TestUtil.rsa().cert).build(CmsAlgorithm.AES128_CBC, DATA);
    Assert.assertNull(ed.getRecipient(TestUtil.ec().cert));
  }

  private static byte[] bcEncrypt(CMSEnvelopedDataGenerator gen, ASN1ObjectIdentifier contentAlg)
      throws Exception {
    return gen.generate(new CMSProcessableByteArray(DATA),
        new JceCMSContentEncryptorBuilder(contentAlg).setProvider(TestUtil.BC).build())
        .getEncoded();
  }

  private static int indexOf(byte[] data, byte[] pattern) {
    outer:
    for (int i = 0; i <= data.length - pattern.length; i++) {
      for (int j = 0; j < pattern.length; j++) {
        if (data[i + j] != pattern[j]) {
          continue outer;
        }
      }
      return i;
    }
    throw new IllegalArgumentException("pattern not found");
  }

}
