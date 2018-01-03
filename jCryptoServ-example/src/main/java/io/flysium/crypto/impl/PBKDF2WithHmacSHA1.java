package io.flysium.crypto.impl;

import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.PBESpec;
import io.flysium.crypto.utils.Util;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 * PBKDF2算法</br>
 * Constructs secret keys using the Password-Based Key Derivation Function function </br>
 * found in PKCS #5 v2.0.</br>
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class PBKDF2WithHmacSHA1 extends PBESpec implements ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "PBKDF2WithHmacSHA1";

  public PBKDF2WithHmacSHA1() {
    super(DEFAULT_ALGORITHM, null);
  }

  public PBKDF2WithHmacSHA1(Provider provider) {
    super(DEFAULT_ALGORITHM, provider);
  }

  public PBKDF2WithHmacSHA1(int keyLength) {
    this();
    this.keyLength = keyLength;
  }

  @Override
  public byte[] encrypt(char[] plainText) {
    AlgorithmParameterSpec parameterSpec =
        (AlgorithmParameterSpec) this.getAlgorithmParameterSpec();
    if (parameterSpec == null || !(parameterSpec instanceof PBEParameterSpec)) {
      fail(new Exception("Invalid AlgorithmParameterSpec!"));
    }
    PBEParameterSpec pbeParameterSpec = (PBEParameterSpec) parameterSpec;
    byte[] salt = pbeParameterSpec.getSalt();
    int iterationCount = pbeParameterSpec.getIterationCount();

    SecretKeyFactory factory = Util.getSecretKeyFactory(algorithm, provider);
    try {
      if (factory != null) {
        KeySpec spec = new PBEKeySpec(plainText, salt, iterationCount, this.keyLength);
        return factory.generateSecret(spec).getEncoded();
      }
    } catch (InvalidKeySpecException e) {
      fail(e);
    }
    return null;
  }

}
