package com.github.samuraislice.cs492pfs.common;

import com.google.common.collect.HashMultimap;
import com.google.common.collect.Multimap;
import com.google.common.collect.Multimaps;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;
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
  private KeyPair keyPair;

  // TODO
  //  Needs support for concurrent access
  //  on disk:
  //    encrypted keypair
  //    signed entries of ident + trusted pubkey
  //  init with password
  //  decrypt keypair
  //  validate & load ident + pubkey

  public boolean exists() {
    return initialized.get() || Files.exists(DATASTORE);
  }

  public boolean init(@NotNull String password) throws GeneralSecurityException {
    // Only allow one initialization attempt to occur at a time.
    // Can reuse object as a lock because it isn't exposed.
    synchronized (initialized) {
      if (initialized.get()) {
        throw new IllegalStateException("Already initialized!");
      }

      if (exists()) {
        // TODO load
        return initialized.compareAndSet(false, true);
      }

      KeyPairGenerator keyGen = KeyPairGenerator.getInstance(CryptoConstants.SIG_SPEC);
      keyGen.initialize(CryptoConstants.SIG_SPEC_BITS, random);
      keyPair = keyGen.generateKeyPair();
      // TODO save
      return initialized.compareAndSet(false, true);
    }
  }

  public @NotNull PublicKey getPublicKey() {
    checkState();
    return keyPair.getPublic();
  }

  public @NotNull Identity getLocalIdentity(@NotNull String identifier) {
    checkState();
    return new Identity(identifier, keyPair.getPublic(), true);
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

    // TODO sign hmac of data?

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
    // TODO verify hmac instead?
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

  public boolean trust(@NotNull Remote remote) {
    checkState();

//    if (remote.verified()) {
//      // If identity is already verified, nothing to do.
//      return true;
//    }
//
//    trustedIdentities.put(identity.identifier(), identity.key());


    // TODO
    return false;
  }

  private void checkState() {
    if (!initialized.get()) {
      throw new IllegalStateException("SecureStorage not initialized!");
    }
  }

}
