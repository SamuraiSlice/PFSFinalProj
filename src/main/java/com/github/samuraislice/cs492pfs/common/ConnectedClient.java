package com.github.samuraislice.cs492pfs.common;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;

public class ConnectedClient {

  private final DataOutputStream stream;
  private final BigInteger sharedSecret; // TODO likely won't be bigint later

  public ConnectedClient(@NotNull DataOutputStream stream, @NotNull BigInteger sharedSecret) {
    this.stream = stream;
    this.sharedSecret = sharedSecret;
  }

  public void sendMessage(@Nullable String message) throws IOException {
    System.out.printf("DEBUG: sending message %s%n", message);
    if (message == null || message.isBlank()) {
      throw new IOException("No message provided!");
    }

    message = message.trim();

    // TODO encrypt message

    PacketUtil.sendMessage(stream, message);
  }

}
