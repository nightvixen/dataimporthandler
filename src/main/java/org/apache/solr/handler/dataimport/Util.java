/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.solr.handler.dataimport;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.GeneralSecurityException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.Charset;
import java.security.MessageDigest;

import org.apache.solr.common.SolrException;
import java.util.Arrays;

/**
 * Static methods for translating Base64 encoded strings to byte arrays
 * and vice-versa. 
 */

public class Util {
  /**
   * This array is a lookup table that translates 6-bit positive integer
   * index values into their "Base64 Alphabet" equivalents as specified
   * in Table 1 of RFC 2045.
   */
  private static final char intToBase64[] = {
          'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
          'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
          'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
          'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
          '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
  };
  /**
   * This array is a lookup table that translates unicode characters
   * drawn from the "Base64 Alphabet" (as specified in Table 1 of RFC 2045)
   * into their 6-bit positive integer equivalents.  Characters that
   * are not in the Base64 alphabet but fall within the bounds of the
   * array are translated to -1.
   */
  private static final byte base64ToInt[] = {
          -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
          -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
          -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54,
          55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1, -1, 0, 1, 2, 3, 4,
          5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
          24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33, 34,
          35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51
  };
  public static String byteArrayToBase64(byte[] a) {
    return byteArrayToBase64(a, 0, a.length);
  }
  public static String byteArrayToBase64(byte[] a, int offset, int len) {
    int aLen = len;
    int numFullGroups = aLen / 3;
    int numBytesInPartialGroup = aLen - 3 * numFullGroups;
    int resultLen = 4 * ((aLen + 2) / 3);
    StringBuilder result = new StringBuilder(resultLen);
    char[] intToAlpha = intToBase64;
    // Translate all full groups from byte array elements to Base64
    int inCursor = offset;
    for (int i = 0; i < numFullGroups; i++) {
      int byte0 = a[inCursor++] & 0xff;
      int byte1 = a[inCursor++] & 0xff;
      int byte2 = a[inCursor++] & 0xff;
      result.append(intToAlpha[byte0 >> 2]);
      result.append(intToAlpha[(byte0 << 4) & 0x3f | (byte1 >> 4)]);
      result.append(intToAlpha[(byte1 << 2) & 0x3f | (byte2 >> 6)]);
      result.append(intToAlpha[byte2 & 0x3f]);
    }
    // Translate partial group if present
    if (numBytesInPartialGroup != 0) {
      int byte0 = a[inCursor++] & 0xff;
      result.append(intToAlpha[byte0 >> 2]);
      if (numBytesInPartialGroup == 1) {
        result.append(intToAlpha[(byte0 << 4) & 0x3f]);
        result.append("==");
      } else {
        // assert numBytesInPartialGroup == 2;
        int byte1 = a[inCursor++] & 0xff;
        result.append(intToAlpha[(byte0 << 4) & 0x3f | (byte1 >> 4)]);
        result.append(intToAlpha[(byte1 << 2) & 0x3f]);
        result.append('=');
      }
    }
    return result.toString();
  }
  public static byte[] base64ToByteArray(String s) {
    byte[] alphaToInt = base64ToInt;
    int sLen = s.length();
    int numGroups = sLen / 4;
    if (4 * numGroups != sLen)
      throw new IllegalArgumentException(
              "String length must be a multiple of four.");
    int missingBytesInLastGroup = 0;
    int numFullGroups = numGroups;
    if (sLen != 0) {
      if (s.charAt(sLen - 1) == '=') {
        missingBytesInLastGroup++;
        numFullGroups--;
      }
      if (s.charAt(sLen - 2) == '=')
        missingBytesInLastGroup++;
    }
    byte[] result = new byte[3 * numGroups - missingBytesInLastGroup];
    // Translate all full groups from base64 to byte array elements
    int inCursor = 0, outCursor = 0;
    for (int i = 0; i < numFullGroups; i++) {
      int ch0 = base64toInt(s.charAt(inCursor++), alphaToInt);
      int ch1 = base64toInt(s.charAt(inCursor++), alphaToInt);
      int ch2 = base64toInt(s.charAt(inCursor++), alphaToInt);
      int ch3 = base64toInt(s.charAt(inCursor++), alphaToInt);
      result[outCursor++] = (byte) ((ch0 << 2) | (ch1 >> 4));
      result[outCursor++] = (byte) ((ch1 << 4) | (ch2 >> 2));
      result[outCursor++] = (byte) ((ch2 << 6) | ch3);
    }
    // Translate partial group, if present
    if (missingBytesInLastGroup != 0) {
      int ch0 = base64toInt(s.charAt(inCursor++), alphaToInt);
      int ch1 = base64toInt(s.charAt(inCursor++), alphaToInt);
      result[outCursor++] = (byte) ((ch0 << 2) | (ch1 >> 4));
      if (missingBytesInLastGroup == 1) {
        int ch2 = base64toInt(s.charAt(inCursor++), alphaToInt);
        result[outCursor++] = (byte) ((ch1 << 4) | (ch2 >> 2));
      }
    }
    // assert inCursor == s.length()-missingBytesInLastGroup;
    // assert outCursor == result.length;
    return result;
  }
  /**
   * Translates the specified character, which is assumed to be in the
   * "Base 64 Alphabet" into its equivalent 6-bit positive integer.
   *
   * @throw IllegalArgumentException or ArrayOutOfBoundsException if
   * c is not in the Base64 Alphabet.
   */
  private static int base64toInt(char c, byte[] alphaToInt) {
    int result = alphaToInt[c];
    if (result < 0)
      throw new IllegalArgumentException("Illegal character " + c);
    return result;
  }


 public static String decodeAES(String base64CipherTxt, String pwd) {
    int[] strengths = new int[]{256, 192, 128};
    Exception e = null;
    for (int strength : strengths) {
      try {
        return decodeAES(base64CipherTxt, pwd, strength);
      } catch (Exception exp) {
        e = exp;
      }
    }
    throw new SolrException(SolrException.ErrorCode.BAD_REQUEST, "Error decoding ", e);
  }


  /**
   * Method copied from blog post https://olabini.se/blog/2006/10/openssl-in-jruby/
   * where it is released into the Public Domain, also see LICENSE.txt
   */
  private static byte[][] evpBytesTokey(int key_len, int iv_len, MessageDigest md,
                                        byte[] salt, byte[] data, int count) {
    byte[][] both = new byte[2][];
    byte[] key = new byte[key_len];
    int key_ix = 0;
    byte[] iv = new byte[iv_len];
    int iv_ix = 0;
    both[0] = key;
    both[1] = iv;
    byte[] md_buf = null;
    int nkey = key_len;
    int niv = iv_len;
    int i = 0;
    if (data == null) {
      return both;
    }
    int addmd = 0;
    for (; ; ) {
      md.reset();
      if (addmd++ > 0) {
        md.update(md_buf);
      }
      md.update(data);
      if (null != salt) {
        md.update(salt, 0, 8);
      }
      md_buf = md.digest();
      for (i = 1; i < count; i++) {
        md.reset();
        md.update(md_buf);
        md_buf = md.digest();
      }
      i = 0;
      if (nkey > 0) {
        for (; ; ) {
          if (nkey == 0)
            break;
          if (i == md_buf.length)
            break;
          key[key_ix++] = md_buf[i];
          nkey--;
          i++;
        }
      }
      if (niv > 0 && i != md_buf.length) {
        for (; ; ) {
          if (niv == 0)
            break;
          if (i == md_buf.length)
            break;
          iv[iv_ix++] = md_buf[i];
          niv--;
          i++;
        }
      }
      if (nkey == 0 && niv == 0) {
        break;
      }
    }
    for (i = 0; i < md_buf.length; i++) {
      md_buf[i] = 0;
    }
    return both;
  }


  /**
   * Code copied from a 2019 Stack Overflow post by Maarten Bodewes
   * https://stackoverflow.com/questions/11783062/how-to-decrypt-file-in-java-encrypted-with-openssl-command-using-aes
   */
  public static String decodeAES(String base64CipherTxt, String pwd, final int keySizeBits) {
    final Charset ASCII = Charset.forName("ASCII");
    final int INDEX_KEY = 0;
    final int INDEX_IV = 1;
    final int ITERATIONS = 1;
    final int SALT_OFFSET = 8;
    final int SALT_SIZE = 8;
    final int CIPHERTEXT_OFFSET = SALT_OFFSET + SALT_SIZE;

    try {
      byte[] headerSaltAndCipherText = base64ToByteArray(base64CipherTxt);

      // --- extract salt & encrypted ---
      // header is "Salted__", ASCII encoded, if salt is being used (the default)
      byte[] salt = Arrays.copyOfRange(
          headerSaltAndCipherText, SALT_OFFSET, SALT_OFFSET + SALT_SIZE);
      byte[] encrypted = Arrays.copyOfRange(
          headerSaltAndCipherText, CIPHERTEXT_OFFSET, headerSaltAndCipherText.length);

      // --- specify cipher and digest for evpBytesTokey method ---

      Cipher aesCBC = Cipher.getInstance("AES/CBC/PKCS5Padding");
      MessageDigest md5 = MessageDigest.getInstance("MD5");

      // --- create key and IV  ---

      // the IV is useless, OpenSSL might as well have use zero's
      final byte[][] keyAndIV = evpBytesTokey(
          keySizeBits / Byte.SIZE,
          aesCBC.getBlockSize(),
          md5,
          salt,
          pwd.getBytes(ASCII),
          ITERATIONS);

      SecretKeySpec key = new SecretKeySpec(keyAndIV[INDEX_KEY], "AES");
      IvParameterSpec iv = new IvParameterSpec(keyAndIV[INDEX_IV]);

      // --- initialize cipher instance and decrypt ---

      aesCBC.init(Cipher.DECRYPT_MODE, key, iv);
      byte[] decrypted = aesCBC.doFinal(encrypted);
      return new String(decrypted, ASCII);
    } catch (BadPaddingException e) {
      // AKA "something went wrong"
      throw new IllegalStateException(
          "Bad password, algorithm, mode or padding;" +
              " no salt, wrong number of iterations or corrupted ciphertext.", e);
    } catch (IllegalBlockSizeException e) {
      throw new IllegalStateException(
          "Bad algorithm, mode or corrupted (resized) ciphertext.", e);
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }
}