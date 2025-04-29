package com.github.samuraislice.cs492pfs.common;

import javax.crypto.Cipher;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class Remote {

  private final DataOutputStream stream;
  private final Cipher encoder;

  public Remote(@NotNull DataOutputStream stream, @NotNull Cipher encoder) {
    this.stream = stream;
    this.encoder = encoder;
  }

  public void sendMessage(@Nullable String message) throws GeneralSecurityException, IOException {
    System.out.printf("DEBUG: sending message %s%n", message);
    if (message == null || message.isBlank()) {
      throw new IOException("No message provided!");
    }

    message = message.trim();

    byte[] encoded = encoder.doFinal(message.getBytes(StandardCharsets.UTF_8));

    PacketUtil.sendPacket(stream, encoded);
  }

}
