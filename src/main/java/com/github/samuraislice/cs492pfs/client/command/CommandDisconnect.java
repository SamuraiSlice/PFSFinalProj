package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.common.Remote;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import java.io.IOException;

public class CommandDisconnect extends Command {

  @Override
  public @NotNull String execute(
      @NotNull ServerConnection server,
      @NotNull ClientConnection client,
      String @NotNull ... args
  ) {
    Remote remote = server.getRemote();
    if (remote == null) {
      remote = client.getRemote();
    }

    if (remote == null) {
      server.open();
      return "Not connected!";
    }

    try {
      remote.disconnect();
      server.open();
      return "Disconnected from " + remote.getIdentifier();
    } catch (IOException e) {
      // TODO logging
      e.printStackTrace();
      return "Error while disconnecting!";
    }

  }

}
