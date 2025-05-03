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
    this.prefix = prefix;
    this.registerCommands();
  }

  public @NotNull String getCommandPrefix() {
    return prefix;
  }

  public @Nullable Command getCommand(@NotNull String command) {
    return commandMap.get(command);
  }

  private void registerCommands() {
    registerCommand(new CommandConnect());
    registerCommand(new CommandDisconnect());
    // TODO command to trust remote
  }

  private void registerCommand(@NotNull Command command) {
    this.commandMap.put(this.prefix + command.getName(), command);
  }

}
