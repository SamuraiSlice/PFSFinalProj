package com.github.samuraislice.cs492pfs.common;

public enum CryptoConstants {
  ;

  public static final String SHARED_KEY_AGREEMENT = "DH";
  public static final int SHARED_PUB_BITS = 2048;

  public static final String CIPHER_MODE = "AES/CBC/PKCS5Padding";

  public static final String SIG_SPEC = "DSA";
  public static final int SIG_SPEC_BITS = 2048;
  public static final int SIG_PUB_LEN = 838; // check PublicKey#getEncoded length if changing spec

  public static final String SIG_ALG = "SHA256withDSA";

}
