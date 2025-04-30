package com.github.samuraislice.cs492pfs.client.command;

import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import java.util.HashMap;
import java.util.Map;

public class CommandManager {

  // Container for registered commands.
  // Client is single-threaded, don't need concurrency.
  private final Map<String, Command> commandMap = new HashMap<>();
  private final @NotNull String prefix;

  public CommandManager(@NotNull String prefix) {
    this.registerCommands();
    this.prefix = prefix;
  }

  public @NotNull String getCommandPrefix() {
    return prefix;
  }

  public @Nullable Command getCommand(@NotNull String name) {
    return commandMap.get(name);
  }

  private void registerCommands() {
    // TODO
    //  connect
    //  disconnect
    //  exit
    //  trust
  }

}
