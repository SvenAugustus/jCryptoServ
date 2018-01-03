package io.flysium.crypto.support;

import io.flysium.crypto.ICryptoSpi;
import org.junit.Assert;

/**
 * Unit Test
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class CryptoSpiUnitTest {

  protected void testEncryptAndDecrypt(ICryptoSpi spi, String plainText) {
    System.out.println("-------Java加密前明文-------" + plainText);
    String ciperTextB64 = spi.encryptStringB64(plainText);
    System.out.println("-------Java加密后密文-------" + ciperTextB64);
    String decryptedText = spi.decryptStringB64(ciperTextB64);
    System.out.println("-------Java解密后明文-------" + decryptedText);
    Assert.assertEquals(plainText, decryptedText);
  }

  protected void testEncryptJsAndDecryptJava(ICryptoSpi spi, String plainText, String jsCiperTextB64)
      throws Exception {
    System.out.println("-------JavaScript加密前明文-------" + plainText);
    System.out.println("-------JavaScript加密后密文-------" + jsCiperTextB64);
    String decryptedText = spi.decryptStringB64(jsCiperTextB64);
    System.out.println("-------Java解密后明文-------" + decryptedText);
    Assert.assertEquals(plainText, decryptedText);
  }


}
