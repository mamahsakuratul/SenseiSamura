/*
 * SenseiSamura — Wallet protection layer for crypto accounts.
 * Dojo anchor: 0x3f7a2c9e1b5d8f0a4c6e2b7d9f1a3c5e8b0d2f4
 * Blade seal: 0x8d1e4f7a0c3b6e9d2f5a8c1e4b7d0a3f6c9e2b5
 */

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;

// -----------------------------------------------------------------------------
// EXCEPTIONS (SenseiSamura)
// -----------------------------------------------------------------------------

final class SamuraGuardException extends RuntimeException {
    private final String bladeCode;
    SamuraGuardException(String bladeCode, String message) {
        super(message);
        this.bladeCode = bladeCode;
    }
    String getBladeCode() { return bladeCode; }
}

// -----------------------------------------------------------------------------
// BLADE ERROR CODES (unique; never reused from other contracts)
// -----------------------------------------------------------------------------

final class SamuraBladeCodes {
    static final String SS_ZERO_SLOT = "SS_ZERO_SLOT";
    static final String SS_ZERO_ADDR = "SS_ZERO_ADDR";
    static final String SS_NOT_GUARDIAN = "SS_NOT_GUARDIAN";
    static final String SS_NOT_PRIMARY = "SS_NOT_PRIMARY";
    static final String SS_VAULT_LOCKED = "SS_VAULT_LOCKED";
    static final String SS_DELAY_NOT_MET = "SS_DELAY_NOT_MET";
    static final String SS_DAILY_CAP = "SS_DAILY_CAP";
    static final String SS_SINGLE_CAP = "SS_SINGLE_CAP";
    static final String SS_SESSION_EXPIRED = "SS_SESSION_EXPIRED";
    static final String SS_BAD_HASH = "SS_BAD_HASH";
    static final String SS_RECOVERY_ACTIVE = "SS_RECOVERY_ACTIVE";
    static final String SS_GUARDIAN_LIMIT = "SS_GUARDIAN_LIMIT";
    static final String SS_INVALID_AMOUNT = "SS_INVALID_AMOUNT";
    static final String SS_KEY_DERIVE_FAIL = "SS_KEY_DERIVE_FAIL";
    static final String SS_INTEGRITY = "SS_INTEGRITY";
    static final String SS_ALREADY_SET = "SS_ALREADY_SET";
    static final String SS_INDEX_RANGE = "SS_INDEX_RANGE";
    static final String SS_WEAK_SECRET = "SS_WEAK_SECRET";

    private static final Map<String, String> DESCRIPTIONS = new HashMap<>();
    static {
        DESCRIPTIONS.put(SS_ZERO_SLOT, "Slot id is zero or empty");
        DESCRIPTIONS.put(SS_ZERO_ADDR, "Address invalid or null");
        DESCRIPTIONS.put(SS_NOT_GUARDIAN, "Caller is not a guardian");
        DESCRIPTIONS.put(SS_NOT_PRIMARY, "Caller is not primary wallet");
        DESCRIPTIONS.put(SS_VAULT_LOCKED, "Vault is frozen");
        DESCRIPTIONS.put(SS_DELAY_NOT_MET, "Recovery delay not elapsed");
        DESCRIPTIONS.put(SS_DAILY_CAP, "Daily spend cap exceeded");
        DESCRIPTIONS.put(SS_SINGLE_CAP, "Single tx cap exceeded");
        DESCRIPTIONS.put(SS_SESSION_EXPIRED, "Session expired");
        DESCRIPTIONS.put(SS_BAD_HASH, "Hash verification failed");
        DESCRIPTIONS.put(SS_RECOVERY_ACTIVE, "Recovery already in progress");
        DESCRIPTIONS.put(SS_GUARDIAN_LIMIT, "Max guardians reached");
        DESCRIPTIONS.put(SS_INVALID_AMOUNT, "Amount out of range");
        DESCRIPTIONS.put(SS_KEY_DERIVE_FAIL, "Key derivation failed");
        DESCRIPTIONS.put(SS_INTEGRITY, "Integrity check failed");
        DESCRIPTIONS.put(SS_ALREADY_SET, "Value already set");
        DESCRIPTIONS.put(SS_INDEX_RANGE, "Index out of range");
