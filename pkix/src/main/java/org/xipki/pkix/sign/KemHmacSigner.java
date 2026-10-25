// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.codec.util.Args;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.XiSecurityException;

import javax.crypto.SecretKey;
import java.io.OutputStream;
import java.security.SignatureException;

/**
 * Kem Hmac Signer definition.
 *
 * @author Lijun Liao (xipki)
 */
public class KemHmacSigner implements Signer {

  private final static AlgorithmIdentifier ALG_ID =
      new AlgorithmIdentifier(XipkiOIDs.id_alg_KEM_HMAC_SHA256);
  private static final byte[] ENCODED_ALG_ID = ALG_ID.getEncoded();

  private final String id;
  private final HmacSigner macSigner;

  public KemHmacSigner(String id, SecretKey macKey) throws XiSecurityException {
    this.id = Args.notNull(id, "id");
    Args.notNull(macKey, "macKey");
    this.macSigner = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
  }

  @Override
  public ContentSigner x509Signer() {
    return new ContentSigner() {
      @Override
      public AlgorithmIdentifier getAlgorithmIdentifier() {
        return ALG_ID;
      }

      @Override
      public OutputStream getOutputStream() {
        return macSigner.x509Signer().getOutputStream();
      }

      @Override
      public byte[] getSignature() throws SignatureException {
        byte[] rawSignature = macSigner.x509Signer().getSignature();
        return new KemHmacSignature(id, rawSignature).getEncoded();
      }

      @Override
      public byte[] atomicSign(byte[] toBeSignData) throws SignatureException {
        byte[] rawSignature = macSigner.x509Signer().atomicSign(toBeSignData);
        return new KemHmacSignature(id, rawSignature).getEncoded();
      }

    };
  }

  @Override
  public byte[] getEncodedX509AlgId() {
    return ENCODED_ALG_ID.clone();
  }
}
