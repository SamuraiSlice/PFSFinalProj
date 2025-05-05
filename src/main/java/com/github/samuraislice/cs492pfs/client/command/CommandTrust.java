package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.common.SecureStorage;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import java.io.IOException;
import java.security.GeneralSecurityException;

public class CommandTrust extends Command {

  @Override
  public String execute(
      @NotNull ServerConnection server,
      @NotNull ClientConnection client,
      String @NotNull ... args
  ) {

    Remote remote = server.getRemote();
    if (remote == null) {
      remote = client.getRemote();
    }

    if (remote == null) {
      return "No one to trust! Connect to someone first.";
    }

    try {
      if (SecureStorage.INSTANCE.trust(remote)) {
        return "Trusted " + remote.getIdentifier() + "!";
      } else {
        return remote.getIdentifier() + " is already trusted!";
      }
    } catch (GeneralSecurityException | IOException e) {
      return "Failed to trust " + remote.getIdentifier() + ": " + e.getMessage();
    }
  }

}
