// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs12;

import org.xipki.codec.util.Args;

/**
 * Keystore Generation Parameters.
 *
 * @author Lijun Liao (xipki)
 */
public class KeystoreGenerationParameters {

  private final char[] password;

  private Boolean unsigned;

  public KeystoreGenerationParameters(char[] password) {
    this.password = Args.notNull(password, "password");
  }

  public char[] password() {
    return password;
  }

  public Boolean unsigned() {
    return unsigned;
  }

  public void setUnsigned(Boolean unsigned) {
    this.unsigned = unsigned;
  }

}
