// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.pkix.asn1.util.ContentVerifier;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeMLDSAPublicKey;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.util.DigestOutputStream;

import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * Composite MLDSAContent Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class CompositeMLDSAContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final DigestOutputStream os;

    private MyContentVerifier(AlgorithmIdentifier algId) {
      this.algId = algId;
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.getInstance(algId);
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException("unknown algorithm " +
            algId.getAlgorithm().getId() + ": " + e.getMessage(), e);
      }

      if (!signAlgo.isCompositeMLDSA()) {
        throw new RuntimeException("algorithm " +
            algId.getAlgorithm().getId() + " is not composite MLDSA");
      }
      this.os = new DigestOutputStream(signAlgo.compositeSigAlgoSuite().ph().createDigest());
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public boolean verify(byte[] signature) {
      try {
        byte[] digestValue = os.digest();
        return CompositeSigUtil.verifyHash(verifyKey, context, digestValue, signature);
      } catch (SignatureException ex) {
        return false;
      } catch (GeneralSecurityException ex) {
        throw new RuntimeException(ex.getMessage());
      }
    }

  } // class EdDSAContentVerifier

  private final CompositeMLDSAPublicKey verifyKey;

  // currently no context is supported
  private final byte[] context = new byte[0];

  public CompositeMLDSAContentVerifierProvider(CompositeMLDSAPublicKey verifyKey) {
    this.verifyKey = Args.notNull(verifyKey, "verifyKey");
  }

  @Override
  public boolean hasAssociatedCertificate() {
    return false;
  }

  @Override
  public Certificate getAssociatedCertificate() {
    return null;
  }

  @Override
  public ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws GenerationException {
    return new MyContentVerifier(verifierAlgorithmIdentifier);
  }

}
