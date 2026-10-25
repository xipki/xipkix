// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.asn1.RuntimeOperatorException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.crypto.core.KeyInfoUtil;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.pkix.asn1.util.SignatureOutputStream;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.util.KeyUtil;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * Signature Signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class SignatureSigner implements Signer {

  private final byte[] encodedX509SigAlgId;

  private final ContentSigner x509Signer;

  public SignatureSigner(
      SignAlgo sigAlgo, Signature signer, SecureRandom random,
      PrivateKey key, byte[] context) throws XiSecurityException {
    this(sigAlgo.algorithmIdentifier(), signer, random, key, context);
  }

  public SignatureSigner(
      AlgorithmIdentifier sigAlgId, Signature signer, SecureRandom random,
      PrivateKey key, byte[] context) throws XiSecurityException {
    Args.notNull(sigAlgId, "sigAlgId");
    Args.notNull(signer, "signer");
    Args.notNull(key, "key");

    this.encodedX509SigAlgId = sigAlgId.getEncoded();

    this.x509Signer = new ContentSigner() {
      private final SignatureOutputStream stream = new SignatureOutputStream(signer);

      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return sigAlgId;
      }

      @Override
      public OutputStream getOutputStream() {
        try {
          KeyUtil.initSign(signer, key, random);
          if (context != null) {
            KeyInfoUtil.setContext(signer, context);
          }
        } catch (InvalidKeyException | InvalidAlgorithmParameterException ex) {
          throw new RuntimeOperatorException("could not initSign", ex);
        }
        return stream;
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        return stream.getSignature();
      }
    };
  }

  /**
   * Creates a {@link ContentSigner} for the software private key.
   * @param signAlgo the signature algorithm.
   * @param key the private key.
   * @return the content signer.
   * @throws XiSecurityException if the signer cannot be created.
   */
  public static ContentSigner newContentSigner(SignAlgo signAlgo, PrivateKey key)
      throws XiSecurityException {
    Args.notNull(signAlgo, "signAlgo");
    Signature signature;
    try {
      signature = CryptoApiFactory.get().newSignature(signAlgo.jceName());
    } catch (GeneralSecurityException e) {
      throw new XiSecurityException("could not create Signature for " + signAlgo, e);
    }
    return new SignatureSigner(signAlgo, signature, null, key, null).x509Signer();
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return Arrays.copyOf(encodedX509SigAlgId, encodedX509SigAlgId.length);
  }

}
