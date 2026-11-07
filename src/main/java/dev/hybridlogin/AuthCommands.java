package dev.hybridlogin;

import org.bukkit.Bukkit;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.entity.Player;

import java.util.Locale;

public final class AuthCommands implements CommandExecutor {
    private final HybridLogin plugin;

    public AuthCommands(HybridLogin plugin) {
        this.plugin = plugin;
    }

    @Override
    public boolean onCommand(CommandSender sender, Command cmd, String label, String[] a) {
        if (!(sender instanceof Player p)) return true;
        switch (cmd.getName().toLowerCase(Locale.ROOT)) {
            case "login" -> login(p, a);
            case "register" -> register(p, a);
            case "changepassword" -> change(p, a);
        }
        return true;
    }

    private void login(Player p, String[] a) {
        if (plugin.isAuthed(p)) { p.sendMessage(plugin.msg("already-logged")); return; }
        if (a.length != 1) { p.sendMessage(plugin.msg("usage-login")); return; }
        if (!plugin.store().isRegistered(p.getName())) { p.sendMessage(plugin.msg("not-registered")); return; }

        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            boolean ok = plugin.store().check(p.getName(), a[0]);
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!p.isOnline()) return;
                if (ok) {
                    plugin.authenticate(p);
                    p.sendMessage(plugin.msg("login-ok"));
                    return;
                }
                int n = plugin.attempts().merge(p.getName().toLowerCase(Locale.ROOT), 1, Integer::sum);
                if (n >= plugin.getConfig().getInt("max-attempts", 5)) {
                    p.kick(plugin.msg("kick-attempts"));
                } else {
                    p.sendMessage(plugin.msg("wrong-password"));
                }
            });
        });
    }

    private void register(Player p, String[] a) {
        if (plugin.isAuthed(p) && plugin.isPremium(p)) { p.sendMessage(plugin.msg("premium-no-password")); return; }
        if (plugin.store().isRegistered(p.getName())) { p.sendMessage(plugin.msg("already-registered")); return; }
        if (a.length != 2) { p.sendMessage(plugin.msg("usage-register")); return; }
        if (!a[0].equals(a[1])) { p.sendMessage(plugin.msg("passwords-differ")); return; }
        if (a[0].length() < plugin.getConfig().getInt("min-password-length", 6)) {
            p.sendMessage(plugin.msg("password-short")); return;
        }
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            plugin.store().setPassword(p.getName(), a[0]);
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (!p.isOnline()) return;
                plugin.authenticate(p);
                p.sendMessage(plugin.msg("register-ok"));
            });
        });
    }

    private void change(Player p, String[] a) {
        if (plugin.isPremium(p)) { p.sendMessage(plugin.msg("premium-no-password")); return; }
        if (!plugin.isAuthed(p)) { p.sendMessage(plugin.msg("must-login")); return; }
        if (a.length != 2) { p.sendMessage(plugin.msg("usage-change")); return; }
        if (a[1].length() < plugin.getConfig().getInt("min-password-length", 6)) {
            p.sendMessage(plugin.msg("password-short")); return;
        }
        Bukkit.getScheduler().runTaskAsynchronously(plugin, () -> {
            boolean ok = plugin.store().check(p.getName(), a[0]);
            if (ok) plugin.store().setPassword(p.getName(), a[1]);
            Bukkit.getScheduler().runTask(plugin, () -> {
                if (p.isOnline()) p.sendMessage(plugin.msg(ok ? "password-changed" : "wrong-password"));
            });
        });
    }
}
