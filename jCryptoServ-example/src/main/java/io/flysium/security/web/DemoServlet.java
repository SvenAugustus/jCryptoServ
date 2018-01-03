package io.flysium.security.web;

import io.flysium.crypto.ICryptoSpi;
import io.flysium.crypto.impl.AES;
import io.flysium.crypto.impl.DES;
import io.flysium.crypto.impl.DESede;
import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * 密钥Demo测试服务
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DemoServlet extends HttpServlet {

  private static final long serialVersionUID = -1874324382371696622L;

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    this.doPost(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    StringBuffer out = new StringBuffer();
    try {
      if (req.getParameter("type") != null) {
        String type = req.getParameter("type");
        String secretKey = req.getParameter("key");
        ICryptoSpi spi = spi(type);
        if (spi != null) {
          spi.setSecret(secretKey.getBytes());
          if (req.getParameter("encrypt") != null) {
            String encrypt = req.getParameter("encrypt");
            String encryptedB64 = spi.encryptStringB64(encrypt);
            out.append("{\"encrypted\":\"");
            out.append(encryptedB64);
            out.append("\"}");
          }
          if (req.getParameter("decrypt") != null) {
            String decrypt = req.getParameter("decrypt");
            String decryptedB64 = spi.decryptStringB64(decrypt);
            out.append("{\"decrypted\":\"");
            out.append(decryptedB64);
            out.append("\"}");
          }
        }
      }
      if (req.getParameter("jCryptoServ") != null) {
        ICryptoSpi spi = CryptoServlet.aesFetchFromSession(req.getSession());
        String decrypt = req.getParameter("decrypt");
        String decryptedB64 = spi.decryptStringB64(decrypt);
        out.append("{\"decrypted\":\"");
        out.append(decryptedB64);
        out.append("\"}");
      }
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      resp.setContentType("application/json;charset=UTF-8");
      resp.setCharacterEncoding("UTF-8");
      resp.getWriter().print(out.toString());
    }
  }

  private static ICryptoSpi spi(String type) {
    ICryptoSpi spi = null;
    if ("AES".equalsIgnoreCase(type)) {
      spi = new AES();
      //spi = new AES("AES/ECB/PKCS5Padding");
    }
    if ("DES".equalsIgnoreCase(type)) {
      spi = new DES();
      //spi = new DES("DES/ECB/PKCS5Padding");
    }
    if ("3DES".equalsIgnoreCase(type)) {
      spi = new DESede();
    }
    return spi;
  }

}
