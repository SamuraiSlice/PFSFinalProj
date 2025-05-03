package com.github.samuraislice.cs492pfs.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.function.Consumer;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

public class Remote {

  private final Object outputLock = new Object();
  private final Object inputLock = new Object();
  private final Socket socket;
  private final DataInputStream inputStream;
  private final DataOutputStream outputStream;
  private final SecretKeySpec keySpec;
  private final SecureRandom random;
  private String identifier;

  Remote(
      @NotNull Socket socket,
      @NotNull DataInputStream inputStream,
      @NotNull DataOutputStream outputStream,
      byte[] sharedSecret
  ) {
    this.socket = socket;
    this.inputStream = inputStream;
    this.outputStream = outputStream;
    // Use first 32 bytes of shared secret as key.
    keySpec = new SecretKeySpec(sharedSecret, 0, 32, "AES");
    random = new SecureRandom(sharedSecret);

    // TODO set up identifier during handshake
    identifier = socket.getInetAddress().toString();
  }

  public String getIdentifier() {
    return identifier;
  }

  public void disconnect() throws IOException {
    PacketUtil.quit(outputStream);
    socket.close();
  }

  public void sendMessage(@Nullable String message) throws GeneralSecurityException, IOException {
    if (message == null || (message = message.trim()).isEmpty()) {
      throw new IOException("No message provided!");
    }

    Cipher encoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    encoder.init(Cipher.ENCRYPT_MODE, keySpec, random);
    byte[] iv = encoder.getIV();

    // Encode message.
    byte[] encoded = encoder.doFinal(message.getBytes(StandardCharsets.UTF_8));

    // Combine all the data.
    byte[] combined = new byte[iv.length + encoded.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encoded, 0, combined, iv.length, encoded.length);

    sendRawData(combined);
  }

  public void sendRawData(byte @NotNull [] data) throws IOException {
    synchronized (outputLock) {
      PacketUtil.sendPacket(outputStream, data);
    }
  }

  public boolean readMessage(@NotNull Logger logger, @NotNull Consumer<String> consumer)
      throws IOException, GeneralSecurityException {
    byte[] rawData = readRawData(logger);

    if (rawData.length == 1 && rawData[0] == -1) {
      consumer.accept("Disconnected.");
      return false;
    }

    if (rawData.length == 0) {
      // Keepalive.
      return true;
    }

    Cipher decoder = Cipher.getInstance("AES/CBC/PKCS5Padding");
    byte[] iv = new byte[decoder.getBlockSize()];
    if (iv.length >= rawData.length) {
      throw new GeneralSecurityException("Unable to read IV!");
    }

    System.arraycopy(rawData, 0, iv, 0, iv.length);
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    decoder.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    byte[] messageData = new byte[rawData.length - iv.length];
    System.arraycopy(rawData, iv.length, messageData, 0, messageData.length);
    messageData = decoder.doFinal(messageData);

    consumer.accept(new String(messageData, StandardCharsets.UTF_8));
    return true;
  }

  public byte[] readRawData(@NotNull Logger logger) throws IOException {
    synchronized (inputLock) {
      return PacketUtil.readPacket(inputStream, logger);
    }
  }

}
