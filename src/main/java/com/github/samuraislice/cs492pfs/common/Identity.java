package com.github.samuraislice.cs492pfs.common;

import java.security.PublicKey;

// TODO should probably make public subclass w/private constructor of SecureStorage
public record Identity(String identifier, PublicKey key, boolean verified) {

  public String getIdentity() {
    if (verified) {
      return identifier;
    }
    return identifier + " (unverified)";
  }

}
