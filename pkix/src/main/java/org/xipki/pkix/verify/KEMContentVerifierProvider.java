// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.verify;

import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.GenerationException;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.asn1.oid.XipkiOIDs;
import org.xipki.pkix.asn1.util.ContentVerifier;
import org.xipki.pkix.asn1.util.ContentVerifierProvider;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.crypto.core.SignAlgo;
import org.xipki.crypto.core.KemUtil;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.pkix.sign.HmacSigner;
import org.xipki.pkix.sign.KemHmacSignature;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SignatureException;

/**
 * KEMContent Verifier Provider.
 *
 * @author Lijun Liao (xipki)
 */
public class KEMContentVerifierProvider implements ContentVerifierProvider {

  private class MyContentVerifier implements ContentVerifier {

    private final AlgorithmIdentifier algId;

    private final HmacSigner verifier;

    private MyContentVerifier(AlgorithmIdentifier algId) throws XiSecurityException {
      this.algId = algId;
      this.verifier = new HmacSigner(SignAlgo.HMAC_SHA256, macKey);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
      return algId;
    }

    @Override
    public OutputStream getOutputStream() {
      return verifier.x509Signer().getOutputStream();
    }

    @Override
    public boolean verify(byte[] expected) throws SignatureException {
      KemHmacSignature expectedSig;
      try {
        expectedSig = KemHmacSignature.decode(expected);
      } catch (CodecException e) {
        return false;
      }

      byte[] rawSignature = expectedSig.signature();
      byte[] computedMacValue = verifier.x509Signer().getSignature();
      return MessageDigest.isEqual(rawSignature, computedMacValue);
    }

  } // class MyContentVerifier

  private final SecretKey macKey;

  public KEMContentVerifierProvider(PublicKey verifyKey, SecretKey ownerMasterKey) {
    Args.notNull(verifyKey, "verifyKey");
    Args.notNull(ownerMasterKey, "ownerMasterKey");

    SubjectPublicKeyInfo subjectPublicKeyInfo;
    try {
      subjectPublicKeyInfo = SubjectPublicKeyInfo.fromPublicKey(verifyKey);
    } catch (CodecException e) {
      throw new IllegalArgumentException("could not parse encoded PublicKey", e);
    }
    byte[] rawPkData = subjectPublicKeyInfo.subjectPublicKey();

    byte[] secret = KemUtil.hmacDerive(ownerMasterKey, 32,
        "XIPKI-KEM".getBytes(StandardCharsets.US_ASCII), rawPkData);
    macKey = new SecretKeySpec(secret, "HMAC");
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
    Asn1Oid oid = verifierAlgorithmIdentifier.getAlgorithm();
    if (!XipkiOIDs.id_alg_KEM_HMAC_SHA256.equals(oid)) {
      throw new GenerationException("unsupported verifierAlgorithmIdentifier " + oid.getId());
    }

    try {
      return new MyContentVerifier(verifierAlgorithmIdentifier);
    } catch (XiSecurityException e) {
      throw new GenerationException(e.getMessage());
    }
  }

}
