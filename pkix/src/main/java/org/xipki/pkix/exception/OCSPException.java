// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.exception;

/**
 * Exception of the OCSP processing.
 *
 * @author Lijun Liao (xipki)
 */
public class OCSPException extends Exception {

  public OCSPException(String message) {
    super(message);
  }

  public OCSPException(String message, Throwable cause) {
    super(message, cause);
  }

}
