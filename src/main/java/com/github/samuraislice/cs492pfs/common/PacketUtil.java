package com.github.samuraislice.cs492pfs.common;

import org.jetbrains.annotations.NotNull;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.logging.Logger;

public enum PacketUtil {
  ;

  public static final int KEEPALIVE_INTERVAL = 10;

  public static void quit(@NotNull DataOutputStream outputStream) throws IOException {
    outputStream.writeInt(1);
    outputStream.write(-1);
  }

  public static void keepalive(@NotNull DataOutputStream outputStream) throws IOException {
    outputStream.writeInt(0);
  }

  public static void sendPacket(
      @NotNull DataOutputStream outputStream,
      byte[] data
  ) throws IOException {
    outputStream.writeInt(data.length);
    outputStream.write(data);
  }

  public static byte[] readPacket(@NotNull DataInputStream stream, @NotNull Logger logger) throws IOException {
    int length = stream.readInt();
    if (length < 0) {
      throw new IOException("Cannot read negative-sized packet!");
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
