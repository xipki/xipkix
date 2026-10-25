// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.pkix.asn1.util;

import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.pkix.asn1.x509.Certificate;

/**
 * General interface for providers of ContentVerifier objects.
 *
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public interface ContentVerifierProvider {

  /**
   * Return whether this verifier has a certificate associated with it.
   *
   * @return true if there is an associated certificate, false otherwise.
   */
  boolean hasAssociatedCertificate();

  /**
   * Return the associated certificate if there is one.
   *
   * @return a holder containing the associated certificate if there is
   *         one, null if there is not.
   */
  Certificate getAssociatedCertificate();

  /**
   * Return a ContentVerifier that matches the passed in algorithm identifier,
   *
   * @param verifierAlgorithmIdentifier the algorithm and parameters required.
   * @return a matching ContentVerifier
   * @throws GenerationException if the required ContentVerifier cannot be created.
   */
  ContentVerifier get(AlgorithmIdentifier verifierAlgorithmIdentifier)
      throws GenerationException;
}
