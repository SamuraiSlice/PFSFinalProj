package com.github.samuraislice.cs492pfs.common;

import java.security.GeneralSecurityException;

/**
 * A {@link GeneralSecurityException} thrown when an {@link ArrayIndexOutOfBoundsException}
 * would occur during decoding.
 */
public class DecodingException extends GeneralSecurityException {

  public DecodingException(String s) {
    super(s);
  }

  public DecodingException(int range, int index) {
    super(String.format("Index out of bounds for range 0 to %d: %d", range, index));
  }

}
