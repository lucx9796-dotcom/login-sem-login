package dev.hybridlogin;

import org.bukkit.configuration.file.YamlConfiguration;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Locale;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/** Guarda as senhas dos piratas em plugins/HybridLogin/accounts.yml (nao toca na playerdata). */
public final class AccountStore {
    private static final int ITERATIONS = 120_000;

    private final File file;
    private final YamlConfiguration yaml;
    private final SecureRandom random = new SecureRandom();

    public AccountStore(File dataFolder) {
        dataFolder.mkdirs();
        this.file = new File(dataFolder, "accounts.yml");
        this.yaml = YamlConfiguration.loadConfiguration(file);
    }

    private static String key(String name) {
        return "accounts." + name.toLowerCase(Locale.ROOT);
    }

    public synchronized boolean isRegistered(String name) {
        return yaml.contains(key(name) + ".hash");
    }

    public synchronized void setPassword(String name, String password) {
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        try {
            yaml.set(key(name) + ".salt", Base64.getEncoder().encodeToString(salt));
            yaml.set(key(name) + ".hash", Base64.getEncoder().encodeToString(pbkdf2(password, salt)));
            yaml.save(file);
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalStateException(e);
        }
    }

    public synchronized boolean check(String name, String password) {
        String salt = yaml.getString(key(name) + ".salt");
        String hash = yaml.getString(key(name) + ".hash");
        if (salt == null || hash == null) return false;
        try {
            byte[] calc = pbkdf2(password, Base64.getDecoder().decode(salt));
            return MessageDigest.isEqual(calc, Base64.getDecoder().decode(hash));
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static byte[] pbkdf2(String password, byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, 256);
        return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
    }
}
