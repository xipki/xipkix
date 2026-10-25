// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cert;

import org.xipki.codec.asn1.crypto.PrivateKeyInfo;
import org.xipki.codec.asn1.crypto.SubjectPublicKeyInfo;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;

import java.security.KeyPair;

/**
 * Key Info Pair.
 *
 * @author Lijun Liao (xipki)
 */
public class KeyInfoPair {

  private final SubjectPublicKeyInfo _public;

  private final PrivateKeyInfo _private;

  public KeyInfoPair(KeyPair keyPair) throws CodecException {
    Args.notNull(keyPair, "keyPair");
    this._private = PrivateKeyInfo.fromPrivateKey(keyPair.getPrivate());
    this._public = SubjectPublicKeyInfo.fromPublicKey(keyPair.getPublic());
  }

  public KeyInfoPair(SubjectPublicKeyInfo _public, PrivateKeyInfo _private) {
    this._private = Args.notNull(_private, "_private");
    this._public = Args.notNull(_public, "_public");
  }

  public SubjectPublicKeyInfo getPublic() {
    return _public;
  }

  public PrivateKeyInfo getPrivate() {
    return _private;
  }
}
