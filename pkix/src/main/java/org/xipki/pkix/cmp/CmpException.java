// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cmp;

/**
 * Exception of the CMP processing.
 *
 * @author Lijun Liao (xipki)
 */
public class CmpException extends Exception {

  public CmpException(String msg, Throwable cause) {
    super(msg, cause);
  }

  public CmpException(String msg) {
    super(msg);
  }

}
