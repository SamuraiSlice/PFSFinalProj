package com.github.samuraislice.cs492pfs.client.command;

import com.github.samuraislice.cs492pfs.client.ClientConnection;
import com.github.samuraislice.cs492pfs.server.ServerConnection;
import org.jetbrains.annotations.NotNull;
import java.util.Locale;

/**
 * Class defining behavior for a client command.
 */
public abstract class Command {

  private final String name;

  protected Command() {
    this.name = getClass().getSimpleName().toLowerCase(Locale.ROOT).replace("command", "");
  }

  /**
   *
   * @return
   */
  public @NotNull String getName() {
    return this.name;
  }

  /**
   * Execute functionality of this command.
   *
   * @param server
   * @param client
   * @param args the arguments including the triggering command
   * @return the command feedback
   */
  public abstract @NotNull String execute(
      @NotNull ServerConnection server,
      @NotNull ClientConnection client,
      String @NotNull ... args
  );

}
