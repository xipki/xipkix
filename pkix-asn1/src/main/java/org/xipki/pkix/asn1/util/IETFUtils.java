// #THIRDPARTY
// Original License (copyright): MIT-style (BouncyCastle)

package org.xipki.pkix.asn1.util;

import org.xipki.codec.asn1.AbstractAsn1String;
import org.xipki.codec.asn1.Asn1Encoding;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.Hex;

/**
 * @author Bouncycastle
 * @author Lijun Liao (xipki)
 */
public class IETFUtils {

  public static String valueToString(Asn1Primitive value) {
    StringBuilder vBuf = new StringBuilder();

    if (value instanceof AbstractAsn1String) { // && !(value instanceof ASN1UniversalString))
      String v = ((AbstractAsn1String)value).getString();
      if (!v.isEmpty() && v.charAt(0) == '#') {
        vBuf.append('\\');
      }

      vBuf.append(v);
    } else {
      vBuf.append('#');
      // -DM Hex.toHexString
      vBuf.append(Hex.encode(value.getEncoded(Asn1Encoding.DER)));
    }

    // Escape in a single linear pass into a fresh builder. The previous implementation escaped by
    // inserting a backslash into the buffer it was scanning (O(n) per insert), so a value of n
    // RFC 4514 special characters - or n leading/trailing spaces - cost ~n^2/2 character moves: a
    // CPU-exhaustion vector for an attacker-supplied large RDN reached via
    // X500Name.toString()/equals()/hashCode(). Output is unchanged.
    int len = vBuf.length();

    // A leading "\#" (produced above when the value begins with '#') is emitted verbatim and the
    // leading-space escaping is suppressed, matching the original phase ordering.
    boolean hashPrefix = len >= 2 && vBuf.charAt(0) == '\\' && vBuf.charAt(1) == '#';

    int firstNonSpace = 0;
    while (firstNonSpace < len && vBuf.charAt(firstNonSpace) == ' ') {
      firstNonSpace++;
    }

    int lastNonSpace = len - 1;
    while (lastNonSpace >= 0 && vBuf.charAt(lastNonSpace) == ' ') {
      lastNonSpace--;
    }

    StringBuilder out = new StringBuilder(len + 16);
    int index = 0;
    if (hashPrefix) {
      out.append("\\#");
      index = 2;
    }

    for (; index < len; index++) {
      char c = vBuf.charAt(index);
      boolean escape;
      switch (c) {
        case ',':
        case '"':
        case '\\':
        case '+':
        case '=':
        case '<':
        case '>':
        case ';':
          escape = true;
          break;
        case ' ':
          // leading spaces escaped only without a "\#" prefix; trailing spaces always escaped.
          escape = (!hashPrefix && index < firstNonSpace) || index > lastNonSpace;
          break;
        default:
          escape = false;
          break;
      }

      if (escape) {
        out.append('\\');
      }

      out.append(c);
    }

    return out.toString();
  }

}
