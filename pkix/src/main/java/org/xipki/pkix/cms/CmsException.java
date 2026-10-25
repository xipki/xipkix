// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

/**
 * Exception of the CMS processing.
 *
 * @author Lijun Liao (xipki)
 */
public class CmsException extends Exception {

  public CmsException(String msg) {
    super(msg);
  }

  public CmsException(String msg, Throwable cause) {
    super(msg, cause);
  }

}
