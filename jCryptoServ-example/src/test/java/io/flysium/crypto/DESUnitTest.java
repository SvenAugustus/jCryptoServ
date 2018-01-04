package io.flysium.crypto;

import io.flysium.crypto.impl.DES;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Test;

/**
 * DES Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DESUnitTest extends CryptoSpiUnitTest {

  @Test
  public void test() {
    ICryptoSpi des = new DES();
    des = new DES("DES/ECB/PKCS5Padding");
    des.generateKey(56);
    System.out.println("-------密钥长度-------" + (des.getSecret().length*8));

    String plainText = "Message";
    testEncryptAndDecrypt(des, plainText);
  }

}
