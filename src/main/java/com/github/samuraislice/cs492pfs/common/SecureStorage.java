package com.github.samuraislice.cs492pfs.common;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;

/**
 * Singleton accessor for the secure datastore.
 */
public enum SecureStorage {
  // Singleton. There should never be more than one secure storage instance.
  INSTANCE;

  private static final Path DATASTORE = Path.of(".datastore");

  private final SecureRandom random = new SecureRandom();
  private final AtomicBoolean initialized = new AtomicBoolean();
  private final Multimap<String, PublicKey> trustedIdentities = Multimaps.synchronizedSetMultimap(
      HashMultimap.create()
  );
  private final byte[] salt = new byte[CryptoConstants.SALT_LEN];
  private KeyPair signingKeyPair;
  private SecretKeySpec keySpec;

  /**
   * Check whether the datastore exists.
   *
   * @return true if the datastore is initialized or the file is available on disk
   */
  public boolean exists() {
    return initialized.get() || Files.exists(DATASTORE);
  }

  /**
   * Initialize the secure datastore.
   *
   * @param password the password used to decrypt the datastore
   * @return true if the datastore is initialized
   * @throws GeneralSecurityException if an issue occurs setting up the datastore
   * @throws IOException if an issue occurs setting up the datastore
   */
  public boolean init(char @NotNull [] password) throws GeneralSecurityException, IOException {
    // Only allow one initialization attempt to occur at a time.
    // Can reuse object as a lock because it isn't exposed.
    synchronized (initialized) {
      if (initialized.get()) {
        throw new IllegalStateException("Already initialized!");
      }

      // Digest password and then remove it from memory.
      MessageDigest digest = MessageDigest.getInstance(CryptoConstants.DIGEST);
      CharBuffer buffer = CharBuffer.wrap(password);
      ByteBuffer encoded = StandardCharsets.UTF_8.encode(buffer);
      digest.update(encoded);
      Arrays.fill(password, (char) 0);
      Arrays.fill(encoded.array(), (byte) 0);

      // If the file exists, load it.
      if (exists()) {
        try {
          load(digest);
        } catch (SignatureException | BadPaddingException | InvalidKeySpecException e) {
          // Usually invalid password.
          return false;
        }
        return initialized.compareAndSet(false, true);
      }

      // Otherwise, generate new datastore.
      // Generate salt and finish digest.
      random.nextBytes(salt);
      digest.update(salt);
      keySpec = new SecretKeySpec(digest.digest(), CryptoConstants.SECRET_KEY_SPEC);

      // Generate a new keypair for signing.
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.SIG_SPEC);
      keyGen.initialize(CryptoConstants.SIG_SPEC_BITS, random);
      signingKeyPair = keyGen.generateKeyPair();

      // Save the new data.
      save();

      return initialized.compareAndSet(false, true);
    }
  }

  /**
   * Load the existing datastore into memory using the given digest as a key.
   *
   * @param digest the digest
   * @throws GeneralSecurityException if the file cannot be decrypted
   * @throws IOException if the file cannot be read
   */
  private void load(@NotNull MessageDigest digest) throws GeneralSecurityException, IOException {
    Decoder base64 = Base64.getDecoder();
    List<String> lines = Files.readAllLines(DATASTORE);

    // Read salt, finish salted password hash.
    String string = lines.remove(0);
    digest.update(base64.decode(string.getBytes(StandardCharsets.UTF_8)));

    keySpec = new SecretKeySpec(digest.digest(), CryptoConstants.SECRET_KEY_SPEC);
    Cipher decoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);

    // Read IV and initialize decoder.
    string = lines.remove(0);
    byte[] iv = base64.decode(string.getBytes(StandardCharsets.UTF_8));
    IvParameterSpec ivSpec = new IvParameterSpec(iv);
    decoder.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

    // Read public key, decode, and decrypt.
    string = lines.remove(0);
    byte[] data = decrypt(decoder, iv, base64.decode(string.getBytes(StandardCharsets.UTF_8)));
    EncodedKeySpec encodedSpec = new X509EncodedKeySpec(data);
    KeyFactory factory = KeyFactory.getInstance(CryptoConstants.SIG_SPEC);
    PublicKey publicKey = factory.generatePublic(encodedSpec);

    // Read private key, decode, and decrypt.
    string = lines.remove(0);
    data = decrypt(decoder, iv, base64.decode(string.getBytes(StandardCharsets.UTF_8)));
    encodedSpec = new PKCS8EncodedKeySpec(data);
    PrivateKey privateKey = factory.generatePrivate(encodedSpec);

    this.signingKeyPair = new KeyPair(publicKey, privateKey);

    // Read signed CBC residue (and ignore trailing newlines).
    do {
      string = lines.remove(lines.size() - 1);
    } while (string.isBlank());
    byte[] signed = base64.decode(string.getBytes(StandardCharsets.UTF_8));

    // Parse trusted identities from remaining lines.
    for (String line : lines) {
      String[] trusted = line.split(":");
      data = decrypt(decoder, iv, base64.decode(trusted[0].getBytes(StandardCharsets.UTF_8)));
      String ident = new String(data, StandardCharsets.UTF_8);
      data = decrypt(decoder, iv, base64.decode(trusted[1].getBytes(StandardCharsets.UTF_8)));
      encodedSpec = new X509EncodedKeySpec(data);
      PublicKey trustedKey = factory.generatePublic(encodedSpec);

      this.trustedIdentities.put(ident, trustedKey);
    }

    // Verify signed CBC residue.
    Signature sig = Signature.getInstance(CryptoConstants.SIG_ALG);
    sig.initVerify(this.signingKeyPair.getPublic());
    sig.update(iv);
    if (sig.verify(signed)) {
      return;
    }

    // If signature is invalid, reject anything that did load.
    this.trustedIdentities.clear();
    this.signingKeyPair = null;
    throw new SignatureException("Invalid password!");
  }

  /**
   * Helper method for decrypting noncontinuous CBC-encoded data.
   *
   * @param decoder the decoding cipher
   * @param iv the IV or CBC residue
   * @param data the data to decrypt
   * @return the decrypted data
   * @throws GeneralSecurityException if the data cannot be decrypted
   */
  private byte[] decrypt(Cipher decoder, byte[] iv, byte[] data) throws  GeneralSecurityException {
    decoder.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
    int blockSize = decoder.getBlockSize();
    System.arraycopy(data, data.length - blockSize, iv, 0, blockSize);
    return decoder.doFinal(data);
  }

  /**
   * Save the datastore to disk.
   *
   * @throws GeneralSecurityException if the datastore cannot be encrypted
   * @throws IOException if the datastore cannot be written
   */
  private void save() throws GeneralSecurityException, IOException {
    // This should only be called from the user input thread, so it shouldn't need extra syncing.
    try (
        BufferedWriter writer = Files.newBufferedWriter(
            DATASTORE,
            StandardOpenOption.WRITE,
            StandardOpenOption.CREATE,
            StandardOpenOption.TRUNCATE_EXISTING
        )
    ) {
      Encoder base64 = Base64.getEncoder();

      // Write salt.
      writer.write(new String(base64.encode(salt), StandardCharsets.UTF_8));
      writer.write('\n');
      Cipher encoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);
      encoder.init(Cipher.ENCRYPT_MODE, keySpec, random);

      // Write IV.
      byte[] iv = encoder.getIV();
      writer.write(new String(base64.encode(iv), StandardCharsets.UTF_8));
      writer.write('\n');

      // Write encoded public and private key.
      writer.write(new String(base64.encode(encrypt(encoder, iv, signingKeyPair.getPublic().getEncoded()))));
      writer.write('\n');
      writer.write(new String(base64.encode(encrypt(encoder, iv, signingKeyPair.getPrivate().getEncoded()))));
      writer.write('\n');

      for (Entry<String, PublicKey> trusted : trustedIdentities.entries()) {
        // Encode handle.
        writer.write(
            new String(
                base64.encode(encrypt(encoder, iv, trusted.getKey().getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8
            )
        );

        // Separator
        writer.write(':');

        // Encode public key.
        writer.write(
            new String(
                base64.encode(encrypt(encoder, iv, trusted.getValue().getEncoded())),
                StandardCharsets.UTF_8
            )
        );

        writer.write('\n');
      }

      byte[] signed = sign0(iv);
      // Write signed residue.
      String data = new String(base64.encode(signed), StandardCharsets.UTF_8);
      writer.write(data);
    }
  }


  /**
   * Helper method for encrypting noncontinuous CBC-encoded data.
   *
   * @param encoder the encoding cipher
   * @param iv the IV or CBC residue
   * @param data the data to encrypt
   * @return the encrypted data
   * @throws GeneralSecurityException if the data cannot be encrypted
   */
  private byte[] encrypt(Cipher encoder, byte[] iv, byte[] data) throws GeneralSecurityException {
    encoder.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
    data = encoder.doFinal(data);
    int blockSize = encoder.getBlockSize();
    System.arraycopy(data, data.length - blockSize, iv, 0, blockSize);
    return data;
  }

  /**
   * Sign data using signing key.
   *
   * @param data the data to produce a signature for
   * @return the signature
   * @throws GeneralSecurityException if an error occurs while signing
   */
  public byte @NotNull [] sign(byte @NotNull [] data) throws GeneralSecurityException {
    checkState();
    return sign0(data);
  }

  ///  Helper method for signing that does not check if the datastore is loaded.
  private byte[] sign0(byte [] data) throws GeneralSecurityException {
    Signature sig = Signature.getInstance(CryptoConstants.SIG_ALG);
    sig.initSign(signingKeyPair.getPrivate(), random);
    sig.update(data);
    return sig.sign();
  }

  /**
   * Send a signed username to a remote.
   *
   * @param identifier the username
   * @param remote the remote person
   * @throws GeneralSecurityException if an issue occurs while encrypting or signing
   * @throws IOException if a communication issue occurs
   */
  public void encodeIdentity(
      @NotNull String identifier,
      @NotNull Remote remote
  ) throws GeneralSecurityException, IOException {
    checkState();

    byte[] key = signingKeyPair.getPublic().getEncoded();
    // Send public key in cleartext. It isn't secret, anyone who connects to us gets it.
    remote.sendRawData(key);

    // Encode our username.
    byte[] data = identifier.getBytes(StandardCharsets.UTF_8);
    data = remote.encode(data, 0, data.length);
    remote.sendRawData(data);

    // Send a signature for the encoded username.
    byte[] signed = sign(data);
    remote.sendRawData(signed);
  }

  /**
   * Receive a signed username from a remote.
   *
   * @param remote the remote person
   * @param logger the logger to send errors to
   * @throws GeneralSecurityException if an issue occurs while decrypting or verifying
   * @throws IOException if a communication issue occurs
   */
  public @NotNull Identity decodeIdentity(
      @NotNull Remote remote,
      @NotNull Logger logger
  ) throws GeneralSecurityException, IOException {
    checkState();

    // Receive public key in cleartext.
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(remote.readRawData(logger));
    KeyFactory factory = KeyFactory.getInstance(CryptoConstants.SIG_SPEC);
    PublicKey clientKey = factory.generatePublic(keySpec);

    // Receive encrypted username.
    byte[] data = remote.readRawData(logger);

    // Prepare to check signature.
    Signature sig = Signature.getInstance(CryptoConstants.SIG_ALG);
    sig.initVerify(clientKey);
    sig.update(data);

    // Verify signature.
    byte[] providedSignature = remote.readRawData(logger);
    if (!sig.verify(providedSignature)) {
      throw new SignatureException("Nope");
    }

    // Decode username.
    data = remote.decode(data, 0, data.length);
    String identifier = new String(data, StandardCharsets.UTF_8);

    // Check for trust.
    boolean trusted = trustedIdentities.containsEntry(identifier, clientKey);

    // Establish identity.
    return new Identity(identifier, clientKey, trusted);
  }

  /**
   * Trust the identity of a remote.
   *
   * @param remote the remote person
   * @return true if the person was not trusted before
   * @throws GeneralSecurityException if an issue occurred saving the datastore
   * @throws IOException if an issue occurred saving the datastore
   */
  public boolean trust(@NotNull Remote remote) throws GeneralSecurityException, IOException {
    checkState();

    Identity identity = remote.getIdentity();
    if (identity == null || identity.verified()) {
      // If identity is already verified, nothing to do.
      return false;
    }

    trustedIdentities.put(identity.identifier(), identity.key());
    remote.setIdentity(new Identity(identity.identifier(), identity.key(), true));

    save();
    return true;
  }

  /// Helper for ensuring that storage is initialized.
  private void checkState() {
    if (!initialized.get()) {
      throw new IllegalStateException("SecureStorage not initialized!");
    }
  }

}
