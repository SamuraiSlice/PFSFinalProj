package com.github.samuraislice.cs492pfs.common;

import javax.crypto.Cipher;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class Remote {

  private final String identifier;
  private final Socket socket;
  private final DataOutputStream stream;
  private final Cipher encoder;

  public Remote(@NotNull Socket socket, @NotNull DataOutputStream stream, @NotNull Cipher encoder) {
    // TODO better identifier like keystore ID
    this.identifier = socket.getInetAddress().toString();
    this.socket = socket;
    this.stream = stream;
    this.encoder = encoder;
  }

  public String getIdentifier() {
    return identifier;
  }

  public void disconnect() throws IOException {
    socket.close();
  }

  public void sendMessage(@Nullable String message) throws GeneralSecurityException, IOException {
    if (message == null || message.isBlank()) {
      throw new IOException("No message provided!");
    }

    message = message.trim();

    byte[] encoded = encoder.doFinal(message.getBytes(StandardCharsets.UTF_8));

    PacketUtil.sendPacket(stream, encoded);
  }

}
