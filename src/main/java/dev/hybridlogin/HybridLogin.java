package dev.hybridlogin;

import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import org.bukkit.Bukkit;
import org.bukkit.entity.Player;
import org.bukkit.plugin.java.JavaPlugin;

import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public final class HybridLogin extends JavaPlugin {
    private record Session(String ip, long at) {}

    private AccountStore store;
    private PremiumVerifier verifier;

    /** Jogadores liberados (originais verificados ou piratas que ja logaram). */
    private final Set<UUID> authed = ConcurrentHashMap.newKeySet();
    /** UUIDs de jogadores originais verificados nesta sessao. */
    private final Set<UUID> premium = ConcurrentHashMap.newKeySet();
    private final Map<String, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    @Override
    public void onEnable() {
        saveDefaultConfig();
        if (Bukkit.getOnlineMode()) {
            getLogger().warning("online-mode=true: piratas NAO conseguem entrar. Use online-mode=false no server.properties.");
        }
        store = new AccountStore(getDataFolder());
        verifier = new PremiumVerifier(this);
        verifier.register();

        getServer().getPluginManager().registerEvents(new AuthListener(this), this);
        AuthCommands commands = new AuthCommands(this);
        for (String name : new String[]{"login", "register", "changepassword"}) {
            getCommand(name).setExecutor(commands);
        }
    }

    public AccountStore store() { return store; }
    public PremiumVerifier verifier() { return verifier; }
    public Set<UUID> premiumUuids() { return premium; }
    public Map<String, Integer> attempts() { return attempts; }

    public boolean isAuthed(Player p) { return authed.contains(p.getUniqueId()); }
    public boolean isPremium(Player p) { return premium.contains(p.getUniqueId()); }

    public void authenticate(Player p) {
        authed.add(p.getUniqueId());
        attempts.remove(p.getName().toLowerCase(Locale.ROOT));
    }

    public void forget(Player p) {
        authed.remove(p.getUniqueId());
        premium.remove(p.getUniqueId());
    }

    public void rememberSession(Player p) {
        if (getConfig().getInt("session-minutes", 0) <= 0 || p.getAddress() == null) return;
        sessions.put(p.getName().toLowerCase(Locale.ROOT),
                new Session(p.getAddress().getAddress().getHostAddress(), System.currentTimeMillis()));
    }

    public boolean hasSession(Player p) {
        int minutes = getConfig().getInt("session-minutes", 0);
        Session s = sessions.get(p.getName().toLowerCase(Locale.ROOT));
        if (minutes <= 0 || s == null || p.getAddress() == null) return false;
        return s.ip().equals(p.getAddress().getAddress().getHostAddress())
                && System.currentTimeMillis() - s.at() <= minutes * 60_000L;
    }

    public String raw(String key) {
        return getConfig().getString("messages." + key, key);
    }

    public Component msg(String key) {
        return LegacyComponentSerializer.legacyAmpersand().deserialize(raw(key));
    }
}
