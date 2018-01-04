package io.flysium.crypto;

import io.flysium.crypto.impl.AES;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Test;

/**
 * AES Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class AESUnitTest extends CryptoSpiUnitTest {

  @Test
  public void test() {
    ICryptoSpi aes = new AES();
    //aes = new AES("AES/ECB/PKCS5Padding");
    aes.generateKey(128);

    String plainText = "JavaScript中文";
    testEncryptAndDecrypt(aes, plainText);
  }

}
