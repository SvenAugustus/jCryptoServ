package io.flysium.crypto;

import io.flysium.crypto.impl.DESede;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Test;

/**
 * DESede Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DESedeUnitTest extends CryptoSpiUnitTest {

  @Test
  public void test() {
    ICryptoSpi desede = new DESede();
    //desede = new DESede("DESede/ECB/PKCS5Padding");
    desede.setKeyLength(112);
    desede.generateKey();
    System.out.println("-------密钥长度-------" + desede.getKeyLength());
    System.out.println("-------Secret长度-------" + desede.getSecret().length);

    String plainText = "JavaScript中文";
    testEncryptAndDecrypt(desede, plainText);
  }


}
