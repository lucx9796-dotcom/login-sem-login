package dev.hybridlogin;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.wrappers.WrappedChatComponent;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.bukkit.Bukkit;
import org.bukkit.ChatColor;
import org.bukkit.entity.Player;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.regex.Pattern;

/**
 * Descobre se o nick e de conta original e, se for, EXIGE prova (handshake de criptografia + Mojang).
 *
 *  - Nick que nao existe na Mojang          -> pirata (segue o fluxo normal, vai precisar de /login)
 *  - Nick de conta original + prova valida   -> original (entra direto, com o UUID oficial)
 *  - Nick de conta original sem prova        -> kick (ninguem pode se passar por outro)
 *
 * Funciona com online-mode=false: a verificacao e feita aqui, so para nicks originais.
 */
public final class PremiumVerifier extends PacketAdapter {
    private static final Pattern VALID_NAME = Pattern.compile("[A-Za-z0-9_]{3,16}");
    private static final long LOOKUP_TTL_MS = 10 * 60_000L;
    private static final long VERIFIED_TTL_MS = 30_000L;

    private record Lookup(boolean premium, long at) {}
    private record Pending(String name, byte[] token, PacketContainer start) {}
    private record Verified(UUID uuid, long at) {}

    private final HybridLogin plugin;
    private final ProtocolManager pm = ProtocolLibrary.getProtocolManager();
    private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
    private final SecureRandom random = new SecureRandom();
    private final KeyPair keyPair;

    private final Map<String, Lookup> lookups = new ConcurrentHashMap<>();
    private final Map<String, Pending> pending = new ConcurrentHashMap<>();
    private final Map<String, Verified> verified = new ConcurrentHashMap<>();

    public PremiumVerifier(HybridLogin plugin) {
        super(PacketAdapter.params()
                .plugin(plugin)
                .clientSide()
                .types(PacketType.Login.Client.START, PacketType.Login.Client.ENCRYPTION_BEGIN)
                .optionAsync());
        this.plugin = plugin;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(1024);
            this.keyPair = gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public void register() {
        pm.getAsynchronousManager().registerAsyncHandler(this).start();
    }

    // ---------- API usada pelo AuthListener ----------

    /** Retorna (e consome) o UUID oficial se este nick acabou de ser verificado. */
    public UUID takeVerified(String name) {
        Verified v = verified.remove(name.toLowerCase(Locale.ROOT));
        if (v == null || System.currentTimeMillis() - v.at() > VERIFIED_TTL_MS) return null;
        return v.uuid();
    }

    /** True se o nick ja foi consultado e pertence a uma conta original. */
    public boolean isPremiumName(String name) {
        Lookup l = lookups.get(name.toLowerCase(Locale.ROOT));
        return l != null && l.premium();
    }

    // ---------- Pacotes ----------

    @Override
    public void onPacketReceiving(PacketEvent e) {
        try {
            if (e.getPacketType() == PacketType.Login.Client.START) onStart(e);
            else onEncryption(e);
        } catch (Exception ex) {
            plugin.getLogger().log(Level.WARNING, "Falha na verificacao de login", ex);
            e.setCancelled(true);
            kick(e.getPlayer(), "kick-error");
        }
    }

    private void onStart(PacketEvent e) throws Exception {
        String name = e.getPacket().getStrings().read(0);
        if (!VALID_NAME.matcher(name).matches()) return; // deixa o servidor rejeitar

        Boolean premium = isPremiumOnMojang(name);
        if (premium == null) { // API fora do ar: nao arrisca deixar alguem se passar por original
            e.setCancelled(true);
            kick(e.getPlayer(), "kick-api-error");
            return;
        }
        if (!premium) return; // pirata: segue normalmente

        // Nick original: segura o Login Start e pede prova ao cliente.
        e.setCancelled(true);
        byte[] token = new byte[4];
        random.nextBytes(token);
        pending.put(key(e.getPlayer()), new Pending(name, token, e.getPacket()));

        PacketContainer req = pm.createPacket(PacketType.Login.Server.ENCRYPTION_BEGIN);
        req.getStrings().write(0, "");
        req.getSpecificModifier(java.security.PublicKey.class).write(0, keyPair.getPublic());
        req.getByteArrays().write(0, token);
        if (req.getBooleans().size() > 0) req.getBooleans().write(0, true); // shouldAuthenticate (1.20.5+)
        pm.sendServerPacket(e.getPlayer(), req);
    }

    private void onEncryption(PacketEvent e) throws Exception {
        e.setCancelled(true); // o servidor (offline) nunca deve ver este pacote
        Player player = e.getPlayer();
        Pending p = pending.remove(key(player));
        if (p == null) { kick(player, "kick-error"); return; }

        Cipher rsa = Cipher.getInstance("RSA");
        rsa.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] token = rsa.doFinal(e.getPacket().getByteArrays().read(1));
        byte[] secret = rsa.doFinal(e.getPacket().getByteArrays().read(0));

        // O cliente ja ligou a criptografia dele; liga a do servidor antes de responder qualquer coisa.
        enableEncryption(player, secret);

        if (!MessageDigest.isEqual(token, p.token())) { kick(player, "kick-premium-failed"); return; }

        UUID uuid = hasJoined(p.name(), serverHash(secret));
        if (uuid == null) { kick(player, "kick-premium-failed"); return; }

        verified.put(p.name().toLowerCase(Locale.ROOT), new Verified(uuid, System.currentTimeMillis()));
        // Agora sim entrega o Login Start original para o servidor seguir o login normal.
        pm.receiveClientPacket(player, p.start());
    }

    // ---------- Mojang ----------

    /** null = nao deu para consultar. */
    private Boolean isPremiumOnMojang(String name) {
        String k = name.toLowerCase(Locale.ROOT);
        Lookup cached = lookups.get(k);
        if (cached != null && System.currentTimeMillis() - cached.at() < LOOKUP_TTL_MS) return cached.premium();
        try {
            HttpRequest req = HttpRequest.newBuilder(URI.create(
                            "https://api.mojang.com/users/profiles/minecraft/" + URLEncoder.encode(name, StandardCharsets.UTF_8)))
                    .timeout(Duration.ofSeconds(5)).GET().build();
            HttpResponse<String> res = http.send(req, HttpResponse.BodyHandlers.ofString());
            int code = res.statusCode();
            if (code == 200) { lookups.put(k, new Lookup(true, System.currentTimeMillis())); return true; }
            if (code == 204 || code == 404) { lookups.put(k, new Lookup(false, System.currentTimeMillis())); return false; }
        } catch (Exception ex) {
            plugin.getLogger().log(Level.WARNING, "Erro consultando a Mojang: " + ex.getMessage());
        }
        return cached != null ? Boolean.valueOf(cached.premium()) : null; // usa cache velho se houver
    }

    private UUID hasJoined(String name, String hash) throws Exception {
        URI uri = URI.create("https://sessionserver.mojang.com/session/minecraft/hasJoined?username="
                + URLEncoder.encode(name, StandardCharsets.UTF_8) + "&serverId=" + hash);
        HttpResponse<String> res = http.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
        if (res.statusCode() != 200) return null;
        JsonObject o = JsonParser.parseString(res.body()).getAsJsonObject();
        String id = o.get("id").getAsString();
        return UUID.fromString(id.replaceFirst(
                "(\\p{XDigit}{8})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}{4})(\\p{XDigit}+)", "$1-$2-$3-$4-$5"));
    }

    private String serverHash(byte[] secret) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-1");
        sha.update(secret);
        sha.update(keyPair.getPublic().getEncoded());
        return new BigInteger(sha.digest()).toString(16); // formato "signed" do Minecraft
    }

    // ---------- Criptografia / kick ----------

    private static String key(Player p) {
        InetSocketAddress a = p.getAddress();
        return String.valueOf(a);
    }

    private void kick(Player player, String msgKey) {
        PacketContainer dc = pm.createPacket(PacketType.Login.Server.DISCONNECT);
        String text = ChatColor.translateAlternateColorCodes('&', plugin.raw(msgKey));
        dc.getChatComponents().write(0, WrappedChatComponent.fromText(text));
        pm.sendServerPacket(player, dc);
    }

    /** Liga o AES/CFB8 no Connection do servidor (mesmo que o vanilla faria no modo online). */
    private void enableEncryption(Player player, byte[] secret) throws Exception {
        Object connection = findConnection(player.getAddress());
        SecretKey key = new SecretKeySpec(secret, "AES");
        Cipher dec = aes(Cipher.DECRYPT_MODE, key);
        Cipher enc = aes(Cipher.ENCRYPT_MODE, key);
        for (Method m : connection.getClass().getMethods()) {
            Class<?>[] t = m.getParameterTypes();
            if (t.length == 2 && t[0] == Cipher.class && t[1] == Cipher.class) {
                m.invoke(connection, dec, enc); // Connection#setEncryptionKey(decrypt, encrypt)
                return;
            }
        }
        throw new IllegalStateException("Connection#setEncryptionKey(Cipher, Cipher) nao encontrado");
    }

    private static Cipher aes(int mode, SecretKey key) throws Exception {
        Cipher c = Cipher.getInstance("AES/CFB8/NoPadding");
        c.init(mode, key, new IvParameterSpec(key.getEncoded()));
        return c;
    }

    @SuppressWarnings("unchecked")
    private Object findConnection(SocketAddress address) throws Exception {
        Object server = Bukkit.getServer().getClass().getMethod("getServer").invoke(Bukkit.getServer());
        Object listener = null;
        for (Method m : server.getClass().getMethods()) {
            if (m.getParameterCount() == 0 && m.getReturnType().getSimpleName().equals("ServerConnectionListener")) {
                listener = m.invoke(server);
                break;
            }
        }
        if (listener == null) throw new IllegalStateException("ServerConnectionListener nao encontrado");

        List<Object> connections = null;
        for (Method m : listener.getClass().getMethods()) {
            if (m.getParameterCount() == 0 && m.getName().equals("getConnections") && List.class.isAssignableFrom(m.getReturnType())) {
                connections = (List<Object>) m.invoke(listener);
                break;
            }
        }
        if (connections == null) throw new IllegalStateException("getConnections nao encontrado");

        List<Object> copy;
        synchronized (connections) { copy = new ArrayList<>(connections); }
        for (Object c : copy) {
            Object remote = c.getClass().getMethod("getRemoteAddress").invoke(c);
            if (address.equals(remote)) return c;
        }
        throw new IllegalStateException("Connection do jogador nao encontrada");
    }
}
