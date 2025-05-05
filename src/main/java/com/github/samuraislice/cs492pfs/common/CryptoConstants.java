package com.github.samuraislice.cs492pfs.common;

public enum CryptoConstants {
  ;

  /// Shared key agreement used for establishing PFS.
  public static final String SHARED_KEY_AGREEMENT = "DH";
  public static final int SHARED_PUB_BITS = 2048;

  /// SecretKeySpec used for encryption and decryption.
  public static final String SECRET_KEY_SPEC = "AES";
  /// Cipher mode.
  public static final String CIPHER_MODE = "AES/CBC/PKCS5Padding";

  /// Signing key specification.
  public static final String SIG_SPEC = "DSA";
  /// Number of bits in signing key.
  public static final int SIG_SPEC_BITS = 2048;

  /// Signing algorithm used for signing and verifying remote identities.
  public static final String SIG_ALG = "SHA256withDSA";

  /// Algorithm used to digest password.
  public static final String DIGEST = "SHA3-256";
  /// Number of bytes in salt. 64 bits is considered sufficient.
  public static final int SALT_LEN = 64 / Byte.SIZE;

}
