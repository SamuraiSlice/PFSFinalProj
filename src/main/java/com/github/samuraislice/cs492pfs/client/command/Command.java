package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;

public abstract class Command {

  private final String name;

  protected Command(String name) {
    this.name = name;
  }

  public String getName() {
    return this.name;
  }

  public abstract void execute(@NotNull ServerConnection server, @NotNull ClientConnection clientConnection, String @NotNull ... args);

}
