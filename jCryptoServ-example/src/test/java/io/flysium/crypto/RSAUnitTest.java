package io.flysium.crypto;

import io.flysium.crypto.impl.RSA;
import io.flysium.crypto.support.AsyCryptoSpiUnitTest;
import org.junit.Test;

/**
 * RSA Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class RSAUnitTest extends AsyCryptoSpiUnitTest {

  @Test
  public void testEncryptAndDecrypt1() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey(1024);

    String plainText = "4ba042f9792ea957b1f3fea42fe74276d05ac011e863c4072191d24231a879ca";
    testEncryptAndDecrypt(rsa, plainText);
  }

  @Test
  public void testEncryptAndDecrypt2() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey(1024);

    String plainText = "Javascript中文";
    testEncryptAndDecrypt(rsa, plainText);
  }

  @Test
  public void testEncryptAndDecrypt3() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey();

    String plainText = "赵客缦胡缨，吴钩霜雪明。银鞍照白马，飒沓如流星。十步杀一人，千里不留行。事了拂衣去，深藏身与名。闲过信陵饮，脱剑膝前横。将炙啖朱亥，持觞劝侯嬴。三杯吐然诺，五岳倒为轻。眼花耳热后，意气素霓生。救赵挥金锤，邯郸先震惊。千秋二壮士，烜赫大梁城。纵死侠骨香，不惭世上英。谁能书阁下，白首太玄经。";
    testEncryptAndDecrypt(rsa, plainText);
  }

  @Test
  public void testSignAndVerify1() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey();

    String text = "4ba042f9792ea957b1f3fea42fe74276d05ac011e863c4072191d24231a879ca";
    testSignAndVerify(rsa, text);
  }

  @Test
  public void testSignAndVerify2() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey();

    String text = "Javascript中文";
    testSignAndVerify(rsa, text);
  }

  @Test
  public void testSignAndVerify3() {
    IAsyCryptoSpi rsa = new RSA();
    rsa.generateKey();

    String text = "赵客缦胡缨，吴钩霜雪明。银鞍照白马，飒沓如流星。十步杀一人，千里不留行。事了拂衣去，深藏身与名。闲过信陵饮，脱剑膝前横。将炙啖朱亥，持觞劝侯嬴。三杯吐然诺，五岳倒为轻。眼花耳热后，意气素霓生。救赵挥金锤，邯郸先震惊。千秋二壮士，烜赫大梁城。纵死侠骨香，不惭世上英。谁能书阁下，白首太玄经。";
    testSignAndVerify(rsa, text);
  }


}
