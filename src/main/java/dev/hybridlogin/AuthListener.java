package dev.hybridlogin;

import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.block.BlockBreakEvent;
import org.bukkit.event.block.BlockPlaceEvent;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityTargetEvent;
import org.bukkit.event.inventory.InventoryClickEvent;
import org.bukkit.event.inventory.InventoryOpenEvent;
import org.bukkit.event.player.AsyncPlayerPreLoginEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEntityEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerMoveEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.event.player.PlayerSwapHandItemsEvent;
import io.papermc.paper.event.player.AsyncChatEvent;

import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/**
 * Importante: nada aqui altera efeitos de pocao, posicao, invulnerabilidade ou inventario.
 * Tudo e bloqueado por eventos, entao a playerdata continua intacta.
 */
public final class AuthListener implements Listener {
    private static final Set<String> ALLOWED = Set.of("login", "l", "register", "reg");

    private final HybridLogin plugin;

    public AuthListener(HybridLogin plugin) {
        this.plugin = plugin;
    }

    // ---------- Identificacao original x pirata ----------

    @EventHandler(priority = EventPriority.LOWEST)
    public void onPreLogin(AsyncPlayerPreLoginEvent e) {
        PremiumVerifier v = plugin.verifier();
        UUID real = v.takeVerified(e.getName());
        if (real != null) {
            // Original verificado: usa o UUID oficial da Mojang -> playerdata original.
            e.setPlayerProfile(Bukkit.createProfile(real, e.getName()));
            plugin.premiumUuids().add(real);
        } else if (v.isPremiumName(e.getName())) {
            // Nick de conta original sem verificacao = alguem tentando se passar por ele.
            e.disallow(AsyncPlayerPreLoginEvent.Result.KICK_OTHER, plugin.msg("kick-premium-name"));
        }
        // Qualquer outro caso = pirata (UUID offline normal), precisa de login.
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onJoin(PlayerJoinEvent e) {
        Player p = e.getPlayer();
        if (plugin.isPremium(p)) {
            plugin.authenticate(p);
            p.sendMessage(plugin.msg("premium-welcome"));
            return;
        }
        if (plugin.hasSession(p)) {
            plugin.authenticate(p);
            p.sendMessage(plugin.msg("session-ok"));
            return;
        }
        boolean registered = plugin.store().isRegistered(p.getName());
        p.sendMessage(plugin.msg(registered ? "please-login" : "please-register"));

        long ticks = plugin.getConfig().getInt("login-timeout-seconds", 60) * 20L;
        Bukkit.getScheduler().runTaskLater(plugin, () -> {
            if (p.isOnline() && !plugin.isAuthed(p)) p.kick(plugin.msg("kick-timeout"));
        }, ticks);
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent e) {
        Player p = e.getPlayer();
        if (plugin.isAuthed(p) && !plugin.isPremium(p)) plugin.rememberSession(p);
        plugin.forget(p);
    }

    // ---------- Bloqueios enquanto nao logou ----------

    private boolean locked(Player p) {
        return !plugin.isAuthed(p);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onCommand(PlayerCommandPreprocessEvent e) {
        if (!locked(e.getPlayer())) return;
        String cmd = e.getMessage().substring(1).split(" ")[0].toLowerCase(Locale.ROOT);
        if (!ALLOWED.contains(cmd)) {
            e.setCancelled(true);
            e.getPlayer().sendMessage(plugin.msg("must-login"));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onMove(PlayerMoveEvent e) {
        if (!locked(e.getPlayer()) || e.getTo() == null) return;
        var from = e.getFrom();
        var to = e.getTo();
        // Deixa girar a camera e cair; bloqueia andar/pular.
        if (from.getX() != to.getX() || from.getZ() != to.getZ() || to.getY() > from.getY()) {
            e.setTo(from.clone().setDirection(to.getDirection()));
        }
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onChat(AsyncChatEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteract(PlayerInteractEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInteractEntity(PlayerInteractEntityEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onBreak(BlockBreakEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onPlace(BlockPlaceEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDrop(PlayerDropItemEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onSwap(PlayerSwapHandItemsEvent e) {
        if (locked(e.getPlayer())) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInvClick(InventoryClickEvent e) {
        if (e.getWhoClicked() instanceof Player p && locked(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onInvOpen(InventoryOpenEvent e) {
        if (e.getPlayer() instanceof Player p && locked(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onDamage(EntityDamageEvent e) {
        if (e.getEntity() instanceof Player p && locked(p)) e.setCancelled(true);
    }

    @EventHandler(priority = EventPriority.LOWEST, ignoreCancelled = true)
    public void onTarget(EntityTargetEvent e) {
        if (e.getTarget() instanceof Player p && locked(p)) e.setCancelled(true);
    }
}
