// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.util;

import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.oid.PkcsOIDs;
import org.xipki.pkix.asn1.pkcs12.PKCS12PBEParams;
import org.xipki.codec.asn1.crypto.EncryptedPrivateKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.crypto.api.CryptoApi;
import org.xipki.crypto.api.CryptoApiFactory;
import org.xipki.pkix.pkcs12.Pkcs12Pbe;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Encrypts a PKCS#8 private key with the PKCS#12 password-based encryption
 * pbeWithSHAAnd3-KeyTripleDES-CBC, as OpenSSL does with
 * {@code openssl pkcs8 -topk8 -v1 PBE-SHA1-3DES}.
 *
 * @author Lijun Liao (xipki)
 */
public final class PKCS8Encryptor {

  private static final CryptoApi crypto = CryptoApiFactory.get();

  private static final int SALT_SIZE = 20;

  private static final int ITERATION_COUNT = 2048;

  private PKCS8Encryptor() {
  }

  public static EncryptedPrivateKeyInfo encrypt(
      PrivateKeyInfo key, char[] password, SecureRandom random) throws GeneralSecurityException {
    Args.notNull(key, "key");
    Args.notNull(password, "password");

    byte[] salt = new byte[SALT_SIZE];
    crypto.getSecureRandom(random).nextBytes(salt);

    AlgorithmIdentifier algId = AlgorithmIdentifier.build(
        PkcsOIDs.pbeWithSHAAnd3_KeyTripleDES_CBC, new PKCS12PBEParams(salt, ITERATION_COUNT));

    Cipher cipher = Pkcs12Pbe.createCipher(Cipher.ENCRYPT_MODE, password, algId, false, random);
    return new EncryptedPrivateKeyInfo(algId, cipher.doFinal(key.getEncoded()));
  }

}
