// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.exception;

/**
 * Bad Input Exception type.
 *
 * @author Lijun Liao (xipki)
 */
public class BadInputException extends Exception {

  public BadInputException(String message) {
    super(message);
  }

  public BadInputException(Throwable cause) {
    super(cause);
  }

  public BadInputException(String message, Throwable cause) {
    super(message, cause);
  }

}
