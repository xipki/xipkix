// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12.test;

import org.junit.Assume;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * JUnit tests to test the signature creation and verification of PKCS#12 token
 * for the signature algorithm SHA256withRSA.
 *
 * @author Lijun Liao (xipki)
 */
public class Pkcs12SHAKE256withRSAPSSTest extends Pkcs12SignVerifyTest {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  @Override
  protected String getPkcs12File() {
    return "src/test/resources/pkcs12test/test1.p12";
  }

  @Override
  protected String getCertificateFile() {
    return "src/test/resources/pkcs12test/test1.der";
  }

  @Override
  protected SignAlgo getSignatureAlgorithm() {
    SignAlgo signAlgo = SignAlgo.RSAPSS_SHAKE256;
    boolean supported = true;
    try {
      cryptoApi.newSignature(signAlgo.jceName());
    } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
      supported = false;
    }
    Assume.assumeTrue(signAlgo.jceName() + " is not supported", supported);
    return signAlgo;
  }

}
