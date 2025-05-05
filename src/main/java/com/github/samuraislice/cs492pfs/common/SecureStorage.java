package com.github.samuraislice.cs492pfs.common;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.jetbrains.annotations.NotNull;

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
  private KeyPair keyPair;
  private SecretKeySpec keySpec;

  public boolean exists() {
    return initialized.get() || Files.exists(DATASTORE);
  }

  public boolean init(@NotNull String password) throws GeneralSecurityException, IOException {
    // Only allow one initialization attempt to occur at a time.
    // Can reuse object as a lock because it isn't exposed.
    synchronized (initialized) {
      if (initialized.get()) {
        throw new IllegalStateException("Already initialized!");
      }

      MessageDigest digest = MessageDigest.getInstance(CryptoConstants.DIGEST);
      digest.update(password.getBytes(StandardCharsets.UTF_8));

      if (exists()) {
        load(digest);
        return initialized.compareAndSet(false, true);
      }

      random.nextBytes(salt);
      digest.update(salt);
      byte[] finalDigest = digest.digest();
      keySpec = new SecretKeySpec(finalDigest, CryptoConstants.SECRET_KEY_SPEC);

      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.SIG_SPEC);
      keyGen.initialize(CryptoConstants.SIG_SPEC_BITS, random);
      keyPair = keyGen.generateKeyPair();

      save();

      return initialized.compareAndSet(false, true);
    }
  }

  private void load(@NotNull MessageDigest digest) throws GeneralSecurityException, IOException {
    Decoder base64 = Base64.getDecoder();
    List<String> lines = Files.readAllLines(DATASTORE);

    // Read salt, finish salted password hash.
    String string = lines.remove(0);
    digest.update(base64.decode(string.getBytes(StandardCharsets.UTF_8)));

    keySpec = new SecretKeySpec(digest.digest(), CryptoConstants.SECRET_KEY_SPEC);
    Cipher decoder = Cipher.getInstance(CryptoConstants.CIPHER_MODE);

    // Read IV, finish cipher setup.
    string = lines.remove(0);

    // Read IV and initialize decoder.
    IvParameterSpec ivSpec = new IvParameterSpec(base64.decode(string.getBytes(StandardCharsets.UTF_8)));
    decoder.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);



    // TODO
    //  decrypt
    //  pub
    //  private
    //  entries
    //  verify
  }

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

      // TODO verify that this actually works:
      //  Ensure that every update pushes out all current blocks without finalizing
      //  May need a helper method to get next IV based on last encoded data or something.
      //  Also, at that point should sign an actual HMAC.

      // Write encoded public and private key.
      writer.write(new String(base64.encode(encoder.update(keyPair.getPublic().getEncoded()))));
      writer.write('\n');
      writer.write(new String(base64.encode(encoder.update(keyPair.getPrivate().getEncoded()))));
      writer.write('\n');

      for (Entry<String, PublicKey> trusted : trustedIdentities.entries()) {
        // Encode handle.
        writer.write(
            new String(
                base64.encode(encoder.update(trusted.getKey().getBytes(StandardCharsets.UTF_8))),
                StandardCharsets.UTF_8
            )
        );

        // Separator
        writer.write(':');

        // Encode public key.
        writer.write(
            new String(
                base64.encode(encoder.update(trusted.getValue().getEncoded())),
                StandardCharsets.UTF_8
            )
        );

        writer.write('\n');
      }

      // Write residue.
      byte[] residue = encoder.doFinal();
      writer.write(new String(base64.encode(residue), StandardCharsets.UTF_8));
      writer.write('\n');

      // Write signed residue.
      writer.write(new String(base64.encode(sign(residue)), StandardCharsets.UTF_8));
    }
  }

  public byte @NotNull [] sign(byte @NotNull [] data) throws GeneralSecurityException {
    checkState();
    Signature sig = Signature.getInstance(CryptoConstants.SIG_ALG);
    sig.initSign(keyPair.getPrivate(), random);
    sig.update(data);
    return sig.sign();
  }

  public void encodeIdentity(
      @NotNull String identifier,
      @NotNull Remote remote
  ) throws GeneralSecurityException, IOException {
    checkState();

    byte[] key = keyPair.getPublic().getEncoded();
    remote.sendRawData(key);

    byte[] data = identifier.getBytes(StandardCharsets.UTF_8);
    data = remote.encode(data, 0, data.length);
    remote.sendRawData(data);

    byte[] signed = sign(data);
    remote.sendRawData(signed);
  }

  public @NotNull Identity decodeIdentity(
      @NotNull Remote remote,
      @NotNull Logger logger
  ) throws GeneralSecurityException, IOException {
    checkState();

    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(remote.readRawData(logger));

    KeyFactory factory = KeyFactory.getInstance(CryptoConstants.SIG_SPEC);
    PublicKey clientKey = factory.generatePublic(keySpec);

    byte[] data = remote.readRawData(logger);


    Signature sig = Signature.getInstance(CryptoConstants.SIG_ALG);
    sig.initVerify(clientKey);
    sig.update(data);

    byte[] providedSignature = remote.readRawData(logger);
    if (!sig.verify(providedSignature)) {
      throw new SignatureException("Nope");
    }

    data = remote.decode(data, 0, data.length);
    String identifier = new String(data, StandardCharsets.UTF_8);

    // TODO are equals and hashcode identical for these?
    //  may need to manually check entries.
    boolean trusted = trustedIdentities.containsEntry(identifier, clientKey);

    return new Identity(identifier, clientKey, trusted);
  }

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

  private void checkState() {
    if (!initialized.get()) {
      throw new IllegalStateException("SecureStorage not initialized!");
    }
  }

}
