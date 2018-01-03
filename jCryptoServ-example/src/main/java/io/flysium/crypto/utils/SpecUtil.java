package io.flysium.crypto.utils;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

/**
 *
 * 加密参数规范工具类
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public final class SpecUtil extends Util {

  private SpecUtil() {}

  /* 默认迭代次数 */
  public static final int DEFAULT_ITERATIONS = 1000;

  /**
   * 构建加密参数规范：初始化向量 (IV)
   *
   * @param iv 向量 (IV)
   * @return
   */
  public static IvParameterSpec buildIV(byte[] iv) {
    return new IvParameterSpec(iv);
  }

  /**
   * 构建加密参数规范：以密码为基础的加密法 (PBE) 使用的参数集合
   *
   * @param salt 盐
   * @return
   */
  public static PBEParameterSpec buildPBE(byte[] salt) {
    return buildPBE(salt, DEFAULT_ITERATIONS);
  }

  /**
   * 构建加密参数规范：以密码为基础的加密法 (PBE) 使用的参数集合
   *
   * @param salt 盐
   * @param iterationCount 迭代次数
   * @return
   */
  public static PBEParameterSpec buildPBE(byte[] salt, int iterationCount) {
    return new PBEParameterSpec(salt, iterationCount);
  }

  /**
   * 构建加密参数规范：以密码为基础的加密法 (PBE) 使用的参数集合
   *
   * @param salt 盐
   * @return
   */
  public static PBEParameterSpec buildPBE(String salt) {
    return buildPBE(salt.getBytes(), DEFAULT_ITERATIONS);
  }


  /**
   * 构建加密参数规范：以密码为基础的加密法 (PBE) 使用的参数集合
   *
   * @param saltHex 盐
   * @return
   */
  public static PBEParameterSpec buildPBEHex(String saltHex) {
    return buildPBEHex(saltHex, DEFAULT_ITERATIONS);
  }

  /**
   * 构建加密参数规范：以密码为基础的加密法 (PBE) 使用的参数集合
   *
   * @param saltHex 盐
   * @param iterationCount 迭代次数
   * @return
   */
  public static PBEParameterSpec buildPBEHex(String saltHex, int iterationCount) {
    return buildPBE(unhex(saltHex), iterationCount);
  }

}
