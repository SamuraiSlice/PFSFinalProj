package com.github.samuraislice.cs492pfs.common;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;
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
  private  final AtomicReference<@Nullable Identity> identity = new AtomicReference<>();
  private final Socket socket;
  private final DataInputStream inputStream;
  private final DataOutputStream outputStream;
  private final SecretKeySpec keySpec;
  private final SecureRandom random;
  private final @NotNull String hostname;

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
    hostname = socket.getInetAddress().toString();
  }

  void setIdentity(@NotNull Identity identity) {
    this.identity.set(identity);
  }

  @Nullable Identity getIdentity() {
    return this.identity.get();
  }

  public String getIdentifier() {
    Identity ident = identity.get();
    if (ident != null) {
      return ident.getIdentity();
    }
    return hostname;
  }

  public void disconnect() throws IOException {
    PacketUtil.quit(outputStream);
    socket.close();
  }

  public void sendMessage(@Nullable String message) throws GeneralSecurityException, IOException {
    if (message == null || (message = message.trim()).isEmpty()) {
      throw new IOException("No message provided!");
    }

    byte[] data = message.getBytes(StandardCharsets.UTF_8);
    data = encode(data, 0, data.length);

    sendRawData(data);

    // TODO could add hmac for non-repudiation
  }

  public byte @NotNull [] encode(byte @NotNull [] data, int offset, int length)
      throws GeneralSecurityException {
    Cipher encoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);
    encoder.init(Cipher.ENCRYPT_MODE, keySpec, random);
    byte[] iv = encoder.getIV();

    // Encode message.
    byte[] encoded = encoder.doFinal(data, offset, length);

    // Combine IV and message data.
    byte[] combined = new byte[iv.length + encoded.length];
    System.arraycopy(iv, 0, combined, 0, iv.length);
    System.arraycopy(encoded, 0, combined, iv.length, encoded.length);

    return combined;
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

    // TODO could verify hmac for non-repudiation

    byte[] messageData = decode(rawData, 0, rawData.length);

    consumer.accept(new String(messageData, StandardCharsets.UTF_8));
    return true;
  }

  public byte @NotNull [] decode(byte @NotNull [] rawData, int offset, int length)
      throws GeneralSecurityException {
    if (offset + length > rawData.length) {
      throw new DecodingException(rawData.length, offset + length);
    } else if (offset < 0) {
      throw new DecodingException(rawData.length, offset);
    }

    // Create decoder instance.
    Cipher decoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);
    int blockSize = decoder.getBlockSize();
    if (blockSize >= rawData.length - offset) {
      throw new DecodingException(rawData.length, offset + blockSize);
    }

    // Read IV and initialize decoder.
    IvParameterSpec ivSpec = new IvParameterSpec(rawData, offset, blockSize);
    decoder.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    // Finalize data.
    return decoder.doFinal(rawData, offset + blockSize, length - blockSize);
  }

  public byte @NotNull [] readRawData(@NotNull Logger logger) throws IOException {
    synchronized (inputLock) {
      return PacketUtil.readPacket(inputStream, logger);
    }
  }

}
