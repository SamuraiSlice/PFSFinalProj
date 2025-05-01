package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;

public class CommandExit extends Command {


  @Override
  public String execute(
      @NotNull ServerConnection server,
      @NotNull ClientConnection client,
      String @NotNull ... args
  ) {
    // TODO Wire launcher close in more elegantly somehow
    System.exit(0);
    return "Woah, you must be some kind of hacker! Radical.";
  }
}
