// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.pkcs11;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.crypto.core.XiSecurityException;
import org.xipki.codec.exception.InvalidConfException;
import org.xipki.pkix.util.misc.StringUtil;

import java.io.Closeable;
import java.io.File;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * P11 Crypt Service Factory.
 *
 * @author Lijun Liao (xipki)
 */
public class P11CryptServiceFactory implements Closeable {

  public static final String DEFAULT_P11MODULE_NAME = "default";

  private static final Logger LOG = LoggerFactory.getLogger(P11CryptServiceFactory.class);

  private static final Map<String, P11Module> modules = new HashMap<>();

  private Map<String, P11ModuleConf> moduleConfs;

  private Set<String> moduleNames;

  private String pkcs11ConfFile = "xipki/security/pkcs11.json";

  private P11SystemConf pkcs11Conf;

  public P11CryptServiceFactory() {
  }

  public synchronized void init() throws InvalidConfException {
    if (moduleConfs != null) {
      return;
    }

    if (pkcs11Conf == null && StringUtil.isBlank(pkcs11ConfFile)) {
      LOG.error("neither pkcs11Conf nor pkcs11ConfFile is configured, could not initialize");
      return;
    }

    if (pkcs11Conf == null) {
      pkcs11Conf = P11SystemConf.parse(new File(pkcs11ConfFile));
    }

    try {
      Map<String, P11ModuleConf> confs = geModuleConfs();
      this.moduleConfs = Collections.unmodifiableMap(confs);
      this.moduleNames = Set.copyOf(confs.keySet());
    } catch (RuntimeException ex) {
      throw new InvalidConfException("could not create P11Conf: " + ex.getMessage(), ex);
    }
  } // method init

  private Map<String, P11ModuleConf> geModuleConfs() throws InvalidConfException {
    List<P11SystemConf.ModuleConf> moduleTypes = pkcs11Conf.modules();
    List<P11SystemConf.MechanismSetConf> mechanismSets = pkcs11Conf.mechanismSets();

    Map<String, P11ModuleConf> confs = new HashMap<>();
    for (P11SystemConf.ModuleConf moduleType : moduleTypes) {
      P11ModuleConf conf = new P11ModuleConf(moduleType, mechanismSets);
      confs.put(conf.name(), conf);
    }

    if (!confs.containsKey(P11CryptServiceFactory.DEFAULT_P11MODULE_NAME)) {
      throw new InvalidConfException("module '"
          + P11CryptServiceFactory.DEFAULT_P11MODULE_NAME + "' is not defined");
    }
    return confs;
  }

  /**
   * Gets the {@link P11Module} of the given module {@code moduleName}.
   * @param moduleName
   *        Module name. {@code null} for default module name.
   * @return the {@link P11Module} of the given module.
   * @throws TokenException
   *         if PKCS#11 token error occurs.
   * @throws XiSecurityException
   *         if security error occurs.
   */
  public synchronized P11Module getP11Module(String moduleName)
      throws XiSecurityException, TokenException {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException(
          "could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }

    if (moduleConfs == null) {
      throw new IllegalStateException("please set pkcs11ConfFile and then call init() first");
    }

    final String name = getModuleName(moduleName);
    P11ModuleConf conf = Optional.ofNullable(moduleConfs.get(name))
        .orElseThrow(() -> new XiSecurityException("PKCS#11 module " + name + " is not defined"));

    P11Module module = modules.get(name);
    if (module == null) {
      module = P11Module.getInstance(conf);
      LOG.info("added PKCS#11 module {}\n{}", name, module.description());
      modules.put(name, module);
    }

    return module;
  } // method getP11CryptService

  private String getModuleName(String moduleName) {
    return (moduleName == null) ? DEFAULT_P11MODULE_NAME : moduleName;
  }

  public void setPkcs11Conf(P11SystemConf conf) {
    this.pkcs11Conf = conf;
    this.pkcs11ConfFile = null;
  }

  @Override
  public void close() {
    modules.clear();
  }

  public Set<String> getModuleNames() {
    try {
      init();
    } catch (InvalidConfException ex) {
      throw new IllegalStateException(
          "could not initialize P11CryptServiceFactory: " + ex.getMessage(), ex);
    }
    return moduleNames;
  }

}
