// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPrivateKey;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.cert.X509Cert;
import org.xipki.pkix.sign.ConcurrentSigner;
import org.xipki.pkix.sign.DfltConcurrentSigner;
import org.xipki.pkix.sign.SignatureSigner;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.util.KeyUtil;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;

/**
 * P12 Content Signer Builder.
 *
 * @author Lijun Liao (xipki)
 */
public class P12ContentSignerBuilder {

  private static final CryptoApi cryptoApi = CryptoApiFactory.get();

  private final PrivateKey key;

  private final PublicKey publicKey;

  private final X509Cert[] certificateChain;

  public P12ContentSignerBuilder(PrivateKey privateKey, PublicKey publicKey) {
    this.key = Args.notNull(privateKey, "privateKey");
    this.publicKey = Args.notNull(publicKey, "publicKey");
    this.certificateChain = null;
  }

  public P12ContentSignerBuilder(KeypairWithCert keypairWithCert) {
    this.key = Args.notNull(keypairWithCert, "keypairWithCert").getKey();
    this.publicKey = keypairWithCert.publicKey();
    this.certificateChain = keypairWithCert.x509CertChain();
  }

  public X509Cert certificate() {
    return (certificateChain != null && certificateChain.length > 0)
        ? certificateChain[0] : null;
  }

  public PrivateKey key() {
    return key;
  }

  public ConcurrentSigner createSigner(SignAlgo signAlgo, int parallelism, SecureRandom random)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");

    List<Signer> signers = new ArrayList<>(Args.positive(parallelism, "parallelism"));

    if (signAlgo.isCompositeMLDSA()) {
      CompositeSigSuite suite = signAlgo.compositeSigAlgoSuite();

      SignAlgo  pqcAlgo = suite.pqcVariant().signAlgo();
      SignAlgo tradAlgo = suite.tradVariant().signAlgo();
      CompositeMLDSAPrivateKey compKey = (CompositeMLDSAPrivateKey) key;

      for (int i = 0; i < parallelism; i++) {
        boolean checkSig = (i == 0);
        Signer pqcSigner = buildSigner(compKey.pqcKey(), pqcAlgo, random, suite.label(), checkSig);
        Signer tradSigner = buildSigner(compKey.tradKey(), tradAlgo, random, null, checkSig);
        Signer signer = new P12CompositeMLDSASigner(signAlgo, pqcSigner, tradSigner);
        signers.add(signer);
      }
    } else {
      for (int i = 0; i < parallelism; i++) {
        signers.add(buildSigner(key, signAlgo, random, null, (i == 0)));
      }
    }

    final boolean mac = false;
    ConcurrentSigner concurrentSigner;
    try {
      concurrentSigner = new DfltConcurrentSigner(mac, signers, key);
    } catch (NoSuchAlgorithmException ex) {
      throw new XiSecurityException(ex.getMessage(), ex);
    }

    if (certificateChain != null) {
      concurrentSigner.setX509CertChain(certificateChain);
    } else {
      concurrentSigner.setPublicKey(publicKey);
    }
    return concurrentSigner;
  } // method createSigner

  private static Signer buildSigner(
      PrivateKey key, SignAlgo signAlgo, SecureRandom random,
      byte[] context, boolean testSignature) throws XiSecurityException {
    Signature signature;
    try {
      signature = cryptoApi.newSignature(signAlgo.jceName());
      KeyUtil.initSign(signature, key, null);
      if (testSignature) {
        signature.update(new byte[]{1, 2, 3, 4});
        signature.sign();
      }
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException("error building Signature for SignAlgo " + signAlgo, e);
    }

    return new SignatureSigner(signAlgo, signature, random, key, context);
  }

}
