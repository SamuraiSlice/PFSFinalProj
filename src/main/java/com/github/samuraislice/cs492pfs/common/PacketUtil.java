package com.github.samuraislice.cs492pfs.common;

import org.jetbrains.annotations.NotNull;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.logging.Logger;

public enum PacketUtil {
  ;

  public static void quit(@NotNull DataOutputStream outputStream) throws IOException {
    outputStream.write(-1);
  }

  public static void keepalive(@NotNull DataOutputStream outputStream) throws IOException {
    outputStream.write(0);
  }

  public static void sendMessage(@NotNull DataOutputStream outputStream, @NotNull String message) throws IOException {
    byte[] bytes = message.getBytes(StandardCharsets.UTF_8);
    outputStream.writeInt(bytes.length);
    outputStream.write(bytes);
  }

  public static void sendPacket(@NotNull DataOutputStream outputStream, @NotNull byte[] data) {

  }

  public static byte[] readPacket(@NotNull DataInputStream stream, @NotNull Logger logger) throws IOException {
    int length = stream.readInt();
    if (length < 0) {
      // TODO handle at usages or retool? Exception to quit is kinda ugly
      throw new IllegalArgumentException("Negative packet length");
    }

    byte[] data = new byte[length];
    int read = stream.read(data);

    if (read == length) {
      // Expected value
      return data;
    }

    logger.warning(() -> String.format("Got %d of expected %d bytes", read, length));

    byte[] actual = new byte[read];
    System.arraycopy(data, 0, actual, 0, read);
    return actual;
  }

}
