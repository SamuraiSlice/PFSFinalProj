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

/**
 * A remote PFS client.
 */
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
    keySpec = new SecretKeySpec(sharedSecret, 0, 32, CryptoConstants.SECRET_KEY_SPEC);
    random = new SecureRandom(sharedSecret);
    hostname = socket.getInetAddress().toString();
  }

  /**
   * Set the identity of the remote person.
   *
   * @param identity the identity
   */
  void setIdentity(@NotNull Identity identity) {
    this.identity.set(identity);
  }

  /**
   * Get the username of the remote person.
   *
   * @return the identity
   */
  @Nullable Identity getIdentity() {
    return this.identity.get();
  }

  /**
   * Get a username for the remote person.
   *
   * @return the identifier
   */
  public String getIdentifier() {
    Identity ident = identity.get();
    if (ident != null) {
      return ident.getIdentity();
    }
    return hostname;
  }

  /**
   * Disconnect from the remote person.
   *
   * @throws IOException if an issue occurs while disconnecting
   */
  public void disconnect() throws IOException {
    PacketUtil.quit(outputStream);
    socket.close();
  }

  /**
   * Send a message to the remote person.
   *
   * @param message the message
   * @throws GeneralSecurityException if an encoding issue occurs
   * @throws IOException if a communication issue occurs
   */
  public void sendMessage(@Nullable String message) throws GeneralSecurityException, IOException {
    if (message == null || (message = message.trim()).isEmpty()) {
      throw new IOException("No message provided!");
    }

    byte[] data = message.getBytes(StandardCharsets.UTF_8);
    data = encode(data, 0, data.length);

    sendRawData(data);

    // TODO could add hmac for non-repudiation
  }

  /**
   * Encode data for the remote using the shared key.
   *
   * @param data the data
   * @param offset the start position of the data to send
   * @param length the length of the data
   * @return the encoded data
   * @throws GeneralSecurityException if an encoding issue occurs
   */
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

  /**
   * Send unencoded data to the remote.
   *
   * @param data the data
   * @throws IOException if an exception occurs
   */
  public void sendRawData(byte @NotNull [] data) throws IOException {
    synchronized (outputLock) {
      PacketUtil.sendPacket(outputStream, data);
    }
  }

  /**
   * Await a message from the remote. Blocks until a message is read.
   *
   * @param logger the logger to log errors to
   * @param consumer the consumer for the next message
   * @return true if a message was read
   * @throws IOException if a communication issue occurred
   * @throws GeneralSecurityException if a decoding issue occurred
   */
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

  /**
   * Decode data from the remote.
   *
   * @param data the data
   * @param offset the start position of the data to decode
   * @param length the length of the data
   * @return the decoded data
   * @throws GeneralSecurityException if a decoding issue occurs
   */
  public byte @NotNull [] decode(byte @NotNull [] data, int offset, int length)
      throws GeneralSecurityException {
    if (offset + length > data.length) {
      throw new DecodingException(data.length, offset + length);
    } else if (offset < 0) {
      throw new DecodingException(data.length, offset);
    }

    // Create decoder instance.
    Cipher decoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);
    int blockSize = decoder.getBlockSize();
    if (blockSize >= data.length - offset) {
      throw new DecodingException(data.length, offset + blockSize);
    }

    // Read IV and initialize decoder.
    IvParameterSpec ivSpec = new IvParameterSpec(data, offset, blockSize);
    decoder.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    // Finalize data.
    return decoder.doFinal(data, offset + blockSize, length - blockSize);
  }

  /**
   * Await raw data from the remote.
   *
   * @param logger the logger to send errors to
   * @throws IOException if an exception occurs
   */
  public byte @NotNull [] readRawData(@NotNull Logger logger) throws IOException {
    synchronized (inputLock) {
      return PacketUtil.readPacket(inputStream, logger);
    }
  }

}
