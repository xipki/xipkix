// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.sign;

import org.xipki.pkix.asn1.util.ContentSigner;
import org.xipki.crypto.core.XiSecurityException;

import java.security.SignatureException;

/**
 * Signer interface.
 * {@link #getEncodedX509AlgId()}.
 *
 * @author Lijun Liao (xipki)
 */
public interface Signer {

  default byte[] x509Sign(byte[] data) throws XiSecurityException {
    try {
      return x509Signer().atomicSign(data);
    } catch (SignatureException e) {
      throw new XiSecurityException(e);
    }
  }

  ContentSigner x509Signer();

  /**
   * returns the encoded algorithm identifier.
   * @return the encoded algorithm identifier.
   */
  byte[] getEncodedX509AlgId();

}
