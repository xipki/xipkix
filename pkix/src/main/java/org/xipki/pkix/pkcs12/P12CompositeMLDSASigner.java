// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.util.Arrays;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.composite.CompositeSigSuite;
import org.xipki.crypto.core.composite.CompositeSigUtil;
import org.xipki.pkix.sign.Signer;
import org.xipki.pkix.util.DigestOutputStream;

import java.io.OutputStream;
import java.security.SignatureException;

/**
 * P12 Composite MLDSASigner signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class P12CompositeMLDSASigner implements Signer {

  private final SignAlgo signAlgo;

  private final CompositeSigSuite algoSuite;

  private final byte[] encodedX509AlgId;

  private final DigestOutputStream os;

  private final Signer pqcSigner;

  private final Signer tradSigner;

  private final MyX509Signer x509Signer;

  private final byte[] context;

  public P12CompositeMLDSASigner(SignAlgo signAlgo, Signer pqcSigner, Signer tradSigner) {
    this.context = new byte[0]; // current no context is supported.
    this.pqcSigner = Args.notNull(pqcSigner, "pqcSigner");
    this.tradSigner = Args.notNull(tradSigner, "tradSigner");

    this.signAlgo = Args.notNull(signAlgo, "signAlgo");
    if (!signAlgo.isCompositeMLDSA()) {
      throw new IllegalArgumentException(signAlgo + " is not composite MLDSA");
    }

    this.encodedX509AlgId = signAlgo.algorithmIdentifier().getEncoded();
    this.algoSuite = signAlgo.compositeSigAlgoSuite();
    this.x509Signer = new MyX509Signer();
    this.os = new DigestOutputStream(algoSuite.ph().createDigest());
  }

  @Override
  public ContentSigner x509Signer() {
    return x509Signer;
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return encodedX509AlgId.clone();
  }

  private class MyX509Signer implements ContentSigner {

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return signAlgo.algorithmIdentifier();
    }

    @Override
    public OutputStream getOutputStream() {
      os.reset();
      return os;
    }

    @Override
    public byte[] getSignature() throws SignatureException {
      byte[] digestValue = os.digest();
      byte[] m_ = CompositeSigUtil.buildM_(algoSuite, context, digestValue);

      byte[]  pqcSig =  pqcSigner.x509Signer().atomicSign(m_);
      byte[] tradSig = tradSigner.x509Signer().atomicSign(m_);
      return Arrays.concatenate(pqcSig, tradSig);
    }
  }

}
