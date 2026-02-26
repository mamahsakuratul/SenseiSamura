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
        DESCRIPTIONS.put(SS_WEAK_SECRET, "Secret does not meet strength");
    }

    static String describe(String code) {
        return DESCRIPTIONS.getOrDefault(code, "Unknown: " + code);
    }

    static List<String> allCodes() {
        return List.of(SS_ZERO_SLOT, SS_ZERO_ADDR, SS_NOT_GUARDIAN, SS_NOT_PRIMARY, SS_VAULT_LOCKED,
            SS_DELAY_NOT_MET, SS_DAILY_CAP, SS_SINGLE_CAP, SS_SESSION_EXPIRED, SS_BAD_HASH,
            SS_RECOVERY_ACTIVE, SS_GUARDIAN_LIMIT, SS_INVALID_AMOUNT, SS_KEY_DERIVE_FAIL,
            SS_INTEGRITY, SS_ALREADY_SET, SS_INDEX_RANGE, SS_WEAK_SECRET);
    }
}

// -----------------------------------------------------------------------------
// WEI SAFE MATH (overflow-safe; unique constants 1847, 3921, 615)
// -----------------------------------------------------------------------------

final class SamuraWeiMath {
    private static final long CAP_SINGLE = 2_000_000_000_000_000_000L;
    private static final long CAP_DAILY = 5_000_000_000_000_000_000L;
    private static final int SCALE_FACTOR = 1847;

    static long addSafe(long a, long b) {
        long r = a + b;
        if ((a ^ r) < 0 && (b ^ r) < 0) throw new SamuraGuardException(SamuraBladeCodes.SS_INTEGRITY, "Wei overflow");
        return r;
    }

    static long subSafe(long a, long b) {
        if (b > a) throw new SamuraGuardException(SamuraBladeCodes.SS_INVALID_AMOUNT, "Wei underflow");
        return a - b;
    }

    static long clampSingle(long amt) {
        if (amt < 0) return 0;
        return Math.min(amt, CAP_SINGLE);
    }

    static long clampDaily(long amt) {
        if (amt < 0) return 0;
        return Math.min(amt, CAP_DAILY);
    }

    static int scaledHash(int value) {
        return (value * SCALE_FACTOR) % 3921;
    }
}

// -----------------------------------------------------------------------------
// SESSION BOUNDS (random blocks: 7150, 432, 2160)
// -----------------------------------------------------------------------------

final class SamuraSessionConfig {
    static final long TTL_MS = TimeUnit.MINUTES.toMillis(137);
    static final int BLOCKS_PER_DAY = 7150;
    static final int RECOVERY_DELAY_BLOCKS = 2160;
    static final int APPROVAL_COOLDOWN_BLOCKS = 432;
    static final int MAX_GUARDIANS = 9;
    static final int MIN_PASSPHRASE_LEN = 12;
    static final int SALT_LEN = 32;
    static final int HASH_ITERATIONS = 61904;
    static final String DOMAIN_ANCHOR = "0x3f7a2c9e1b5d8f0a4c6e2b7d9f1a3c5e8b0d2f4";
    static final String SEAL_HEX = "0x8d1e4f7a0c3b6e9d2f5a8c1e4b7d0a3f6c9e2b5";
}

// -----------------------------------------------------------------------------
// KEY DERIVATION STUB (wallet protection; no real crypto in stub)
// -----------------------------------------------------------------------------

final class SamuraKeyDerivation {
    private final byte[] salt;
    private final int iterations;

    SamuraKeyDerivation(byte[] salt, int iterations) {
        this.salt = Objects.requireNonNull(salt);
        this.iterations = Math.max(1024, iterations % 100000);
    }

    byte[] derive(char[] passphrase) {
        if (passphrase == null || passphrase.length < SamuraSessionConfig.MIN_PASSPHRASE_LEN) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_WEAK_SECRET, "Passphrase too short");
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] input = new String(passphrase).getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < iterations; i++) {
                md.update(input);
                md.update(salt);
                input = md.digest();
            }
            return input;
        } catch (Exception e) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_KEY_DERIVE_FAIL, e.getMessage());
        }
    }

    static byte[] randomSalt() {
        byte[] b = new byte[SamuraSessionConfig.SALT_LEN];
        new SecureRandom().nextBytes(b);
        return b;
    }
}

// -----------------------------------------------------------------------------
// SPEND RECORD (single tx and rolling window)
// -----------------------------------------------------------------------------

final class SamuraSpendRecord {
    private final String toAddress;
    private final long amountWei;
    private final long blockNum;
    private final long timestampMs;

    SamuraSpendRecord(String toAddress, long amountWei, long blockNum, long timestampMs) {
        this.toAddress = Objects.requireNonNull(toAddress);
        this.amountWei = amountWei;
        this.blockNum = blockNum;
        this.timestampMs = timestampMs;
    }

    String getToAddress() { return toAddress; }
    long getAmountWei() { return amountWei; }
    long getBlockNum() { return blockNum; }
    long getTimestampMs() { return timestampMs; }
}

// -----------------------------------------------------------------------------
// ROLLING DAY WINDOW (7150 blocks)
// -----------------------------------------------------------------------------

final class SamuraRollingDayWindow {
    private final List<SamuraSpendRecord> records = new LinkedList<>();
    private long windowStartBlock;
    private long rollingSpent;
    private static final int WINDOW_BLOCKS = SamuraSessionConfig.BLOCKS_PER_DAY;

    SamuraRollingDayWindow(long currentBlock) {
        this.windowStartBlock = currentBlock;
        this.rollingSpent = 0;
    }

    void addSpend(String to, long amountWei, long blockNum, long timestampMs) {
        advanceWindow(blockNum);
        records.add(new SamuraSpendRecord(to, amountWei, blockNum, timestampMs));
        rollingSpent = SamuraWeiMath.addSafe(rollingSpent, amountWei);
    }

    private void advanceWindow(long currentBlock) {
        while (!records.isEmpty() && currentBlock >= windowStartBlock + WINDOW_BLOCKS) {
            SamuraSpendRecord first = records.get(0);
            if (first.getBlockNum() < windowStartBlock + WINDOW_BLOCKS) {
                rollingSpent = SamuraWeiMath.subSafe(rollingSpent, first.getAmountWei());
                records.remove(0);
            }
            windowStartBlock += WINDOW_BLOCKS;
        }
        if (records.isEmpty()) windowStartBlock = currentBlock;
    }

    long getRollingSpent(long currentBlock) {
        advanceWindow(currentBlock);
        return rollingSpent;
    }

    int getRecordCount() { return records.size(); }
}

// -----------------------------------------------------------------------------
// RECOVERY REQUEST (delay 2160 blocks)
// -----------------------------------------------------------------------------

final class SamuraRecoveryRequest {
    private final String newPrimaryAddress;
    private final long requestedAtBlock;
    private boolean executed;

    SamuraRecoveryRequest(String newPrimaryAddress, long requestedAtBlock) {
        if (newPrimaryAddress == null || newPrimaryAddress.isEmpty()) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_ZERO_ADDR, "Recovery target null");
        }
        this.newPrimaryAddress = newPrimaryAddress;
        this.requestedAtBlock = requestedAtBlock;
        this.executed = false;
    }

    String getNewPrimaryAddress() { return newPrimaryAddress; }
    long getRequestedAtBlock() { return requestedAtBlock; }
    boolean isExecuted() { return executed; }
    void markExecuted() { this.executed = true; }

    boolean isDelayMet(long currentBlock) {
        return currentBlock >= requestedAtBlock + SamuraSessionConfig.RECOVERY_DELAY_BLOCKS;
    }
}

// -----------------------------------------------------------------------------
// GUARDIAN SET (max 9)
// -----------------------------------------------------------------------------

final class SamuraGuardianSet {
    private final Set<String> guardians = ConcurrentHashMap.newKeySet();
    private final int maxGuardians = SamuraSessionConfig.MAX_GUARDIANS;

    void add(String address) {
        if (address == null || address.isEmpty()) throw new SamuraGuardException(SamuraBladeCodes.SS_ZERO_ADDR, "Guardian addr null");
        if (guardians.size() >= maxGuardians) throw new SamuraGuardException(SamuraBladeCodes.SS_GUARDIAN_LIMIT, "Max guardians");
        guardians.add(address);
    }

    void remove(String address) {
        guardians.remove(address);
    }

    boolean contains(String address) {
        return guardians.contains(address);
    }

    int size() { return guardians.size(); }
    Set<String> snapshot() { return new HashSet<>(guardians); }
}

// -----------------------------------------------------------------------------
// SESSION (TTL 137 minutes)
// -----------------------------------------------------------------------------

final class SamuraSession {
    private final String sessionId;
    private final String primaryAddress;
    private final long createdAtMs;
    private final long ttlMs;

    SamuraSession(String sessionId, String primaryAddress, long createdAtMs) {
        this.sessionId = Objects.requireNonNull(sessionId);
        this.primaryAddress = Objects.requireNonNull(primaryAddress);
        this.createdAtMs = createdAtMs;
        this.ttlMs = SamuraSessionConfig.TTL_MS;
    }

    boolean isExpired(long nowMs) {
        return nowMs > createdAtMs + ttlMs;
    }

    String getSessionId() { return sessionId; }
    String getPrimaryAddress() { return primaryAddress; }
}

// -----------------------------------------------------------------------------
// VAULT STATE (primary, frozen, recovery)
// -----------------------------------------------------------------------------

final class SamuraVaultState {
    private String primaryAddress;
    private volatile boolean frozen;
    private SamuraRecoveryRequest recoveryRequest;
    private final SamuraGuardianSet guardianSet;
    private final SamuraRollingDayWindow rollingWindow;
    private long currentBlockSim;

    SamuraVaultState(String primaryAddress, long initialBlock) {
        if (primaryAddress == null || primaryAddress.isEmpty()) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_ZERO_ADDR, "Primary null");
        }
        this.primaryAddress = primaryAddress;
        this.frozen = false;
        this.recoveryRequest = null;
        this.guardianSet = new SamuraGuardianSet();
        this.rollingWindow = new SamuraRollingDayWindow(initialBlock);
        this.currentBlockSim = initialBlock;
    }

    String getPrimaryAddress() { return primaryAddress; }
    boolean isFrozen() { return frozen; }
    void setFrozen(boolean f) { this.frozen = f; }
    void setPrimaryAddress(String addr) { this.primaryAddress = addr; }
    SamuraRecoveryRequest getRecoveryRequest() { return recoveryRequest; }
    void setRecoveryRequest(SamuraRecoveryRequest r) { this.recoveryRequest = r; }
    SamuraGuardianSet getGuardianSet() { return guardianSet; }
    SamuraRollingDayWindow getRollingWindow() { return rollingWindow; }
    long getCurrentBlockSim() { return currentBlockSim; }
    void setCurrentBlockSim(long b) { this.currentBlockSim = b; }
}

// -----------------------------------------------------------------------------
// AUDIT LOG ENTRY (immutable record)
// -----------------------------------------------------------------------------

final class SamuraAuditEntry {
    private final long seq;
    private final int kind;
    private final String actor;
    private final String target;
    private final long valueWei;
    private final long blockNum;
    private final long timestampMs;
    private static final int KIND_SPEND = 1;
    private static final int KIND_RECOVERY_REQ = 2;
    private static final int KIND_RECOVERY_EXEC = 3;
    private static final int KIND_FREEZE = 4;
    private static final int KIND_GUARDIAN_ADD = 5;
    private static final int KIND_GUARDIAN_REMOVE = 6;
    private static final int MAX_ENTRIES = 8473;

    SamuraAuditEntry(long seq, int kind, String actor, String target, long valueWei, long blockNum, long timestampMs) {
        this.seq = seq;
        this.kind = kind;
        this.actor = actor;
        this.target = target;
        this.valueWei = valueWei;
        this.blockNum = blockNum;
        this.timestampMs = timestampMs;
    }

    long getSeq() { return seq; }
    int getKind() { return kind; }
    String getActor() { return actor; }
    String getTarget() { return target; }
    long getValueWei() { return valueWei; }
    long getBlockNum() { return blockNum; }
    long getTimestampMs() { return timestampMs; }
}

// -----------------------------------------------------------------------------
// AUDIT LOG (bounded ring; 8473 entries)
// -----------------------------------------------------------------------------

final class SamuraAuditLog {
    private final List<SamuraAuditEntry> entries = Collections.synchronizedList(new ArrayList<>());
    private final AtomicLong sequence = new AtomicLong(392);
    private static final int MAX = 8473;

    void append(int kind, String actor, String target, long valueWei, long blockNum, long timestampMs) {
        long seq = sequence.incrementAndGet();
        entries.add(new SamuraAuditEntry(seq, kind, actor, target, valueWei, blockNum, timestampMs));
        if (entries.size() > MAX) entries.remove(0);
    }

    List<SamuraAuditEntry> getRecent(int n) {
        int size = entries.size();
        if (n <= 0 || size == 0) return List.of();
        int from = Math.max(0, size - n);
        return new ArrayList<>(entries.subList(from, size));
    }

    int size() { return entries.size(); }
}

// -----------------------------------------------------------------------------
// ADDRESS BOOK (whitelist for allowed recipients; max 619)
// -----------------------------------------------------------------------------

final class SamuraAddressBook {
    private final Set<String> allowed = ConcurrentHashMap.newKeySet();
    private final Map<String, Long> addedAtBlock = new ConcurrentHashMap<>();
    private static final int MAX_ENTRIES = 619;

    void add(String address, long blockNum) {
        if (address == null || address.isEmpty()) throw new SamuraGuardException(SamuraBladeCodes.SS_ZERO_ADDR, "Addr null");
        if (allowed.size() >= MAX_ENTRIES) throw new SamuraGuardException(SamuraBladeCodes.SS_INDEX_RANGE, "Address book full");
        allowed.add(address);
        addedAtBlock.put(address, blockNum);
    }

    void remove(String address) {
        allowed.remove(address);
        addedAtBlock.remove(address);
    }

    boolean isAllowed(String address) { return allowed.contains(address); }
    int size() { return allowed.size(); }
    Set<String> snapshot() { return new HashSet<>(allowed); }
}

// -----------------------------------------------------------------------------
// RATE LIMITER (per-actor; 137 actions per 7150 blocks)
// -----------------------------------------------------------------------------

final class SamuraRateLimiter {
    private final Map<String, LinkedList<Long>> blocksByActor = new ConcurrentHashMap<>();
    private static final int WINDOW_BLOCKS = 7150;
    private static final int MAX_ACTIONS = 137;

    boolean allow(String actor, long currentBlock) {
        LinkedList<Long> list = blocksByActor.computeIfAbsent(actor, k -> new LinkedList<>());
        synchronized (list) {
            while (!list.isEmpty() && currentBlock - list.getFirst() > WINDOW_BLOCKS) list.removeFirst();
            if (list.size() >= MAX_ACTIONS) return false;
            list.add(currentBlock);
            return true;
        }
    }

    int remaining(String actor, long currentBlock) {
        LinkedList<Long> list = blocksByActor.get(actor);
        if (list == null) return MAX_ACTIONS;
        synchronized (list) {
            while (!list.isEmpty() && currentBlock - list.getFirst() > WINDOW_BLOCKS) list.removeFirst();
            return Math.max(0, MAX_ACTIONS - list.size());
        }
    }
}

// -----------------------------------------------------------------------------
// POLICY RULE (spend limit tier by label)
// -----------------------------------------------------------------------------

final class SamuraPolicyRule {
    private final String label;
    private final long maxWeiPerTx;
    private final long maxWeiPerDay;
    private final int priority;

    SamuraPolicyRule(String label, long maxWeiPerTx, long maxWeiPerDay, int priority) {
        this.label = label;
        this.maxWeiPerTx = maxWeiPerTx;
        this.maxWeiPerDay = maxWeiPerDay;
        this.priority = priority;
    }

    String getLabel() { return label; }
    long getMaxWeiPerTx() { return maxWeiPerTx; }
    long getMaxWeiPerDay() { return maxWeiPerDay; }
    int getPriority() { return priority; }
}

// -----------------------------------------------------------------------------
// POLICY ENGINE (evaluate rules; constants 2847, 501)
// -----------------------------------------------------------------------------

final class SamuraPolicyEngine {
    private final List<SamuraPolicyRule> rules = new ArrayList<>();
    private static final long DEFAULT_TX_CAP = 2_000_000_000_000_000_000L;
    private static final long DEFAULT_DAY_CAP = 5_000_000_000_000_000_000L;
    private static final int RULE_LIMIT = 47;

    void addRule(SamuraPolicyRule rule) {
        if (rules.size() >= RULE_LIMIT) throw new SamuraGuardException(SamuraBladeCodes.SS_INDEX_RANGE, "Too many rules");
        rules.add(rule);
        rules.sort((a, b) -> Integer.compare(b.getPriority(), a.getPriority()));
    }

    boolean allowTx(long amountWei, long daySpentSoFar, String label) {
        long txCap = DEFAULT_TX_CAP;
        long dayCap = DEFAULT_DAY_CAP;
        for (SamuraPolicyRule r : rules) {
            if (label != null && label.equals(r.getLabel())) {
                txCap = r.getMaxWeiPerTx();
                dayCap = r.getMaxWeiPerDay();
                break;
            }
        }
        return amountWei > 0 && amountWei <= txCap && (daySpentSoFar + amountWei) <= dayCap;
    }

    int ruleCount() { return rules.size(); }
}

// -----------------------------------------------------------------------------
// BACKUP HASH (integrity check for exported state)
// -----------------------------------------------------------------------------

final class SamuraBackupHash {
    private final byte[] hash;
    private final long blockNum;
    private final long timestampMs;

    SamuraBackupHash(byte[] hash, long blockNum, long timestampMs) {
        this.hash = hash != null ? hash.clone() : new byte[0];
        this.blockNum = blockNum;
        this.timestampMs = timestampMs;
    }

    byte[] getHash() { return hash.clone(); }
    long getBlockNum() { return blockNum; }
    long getTimestampMs() { return timestampMs; }

    boolean matches(byte[] data) {
        byte[] computed = SenseiSamuraWalletProtection.hashForIntegrity(data);
        return MessageDigest.isEqual(hash, computed);
    }
}

// -----------------------------------------------------------------------------
// ENCRYPTION ENVELOPE (stub: stores nonce + tag for AEAD-style)
// -----------------------------------------------------------------------------

final class SamuraEncryptionEnvelope {
    private final byte[] nonce;
    private final byte[] tag;
    private final int version;
    private static final int NONCE_LEN = 24;
    private static final int TAG_LEN = 16;
    private static final int VERSION = 3;

    SamuraEncryptionEnvelope(byte[] nonce, byte[] tag, int version) {
        this.nonce = nonce != null && nonce.length >= NONCE_LEN ? nonce.clone() : new byte[NONCE_LEN];
        this.tag = tag != null && tag.length >= TAG_LEN ? tag.clone() : new byte[TAG_LEN];
        this.version = version >= 1 ? version : VERSION;
    }

    static SamuraEncryptionEnvelope createNew() {
        SecureRandom sr = new SecureRandom();
        byte[] nonce = new byte[NONCE_LEN];
        byte[] tag = new byte[TAG_LEN];
        sr.nextBytes(nonce);
        sr.nextBytes(tag);
        return new SamuraEncryptionEnvelope(nonce, tag, VERSION);
    }

    byte[] getNonce() { return nonce.clone(); }
    byte[] getTag() { return tag.clone(); }
    int getVersion() { return version; }
}

// -----------------------------------------------------------------------------
// APPROVAL DELAY (432 blocks cooldown)
// -----------------------------------------------------------------------------

final class SamuraApprovalDelay {
    private long lastApprovalBlock;
    private static final int COOLDOWN = SamuraSessionConfig.APPROVAL_COOLDOWN_BLOCKS;

    SamuraApprovalDelay(long currentBlock) {
        this.lastApprovalBlock = 0;
    }

    boolean canApprove(long currentBlock) {
        return currentBlock >= lastApprovalBlock + COOLDOWN;
    }

    void recordApproval(long currentBlock) {
        this.lastApprovalBlock = currentBlock;
    }
}

// -----------------------------------------------------------------------------
// MAIN VAULT CONTROLLER (orchestrates all)
// -----------------------------------------------------------------------------

public final class SenseiSamuraWalletProtection {
    private final SamuraVaultState state;
    private final Map<String, SamuraSession> sessions = new ConcurrentHashMap<>();
    private final AtomicLong sessionCounter = new AtomicLong(2103);
    private static final long DAILY_CAP_WEI = 5_000_000_000_000_000_000L;
    private static final long SINGLE_CAP_WEI = 2_000_000_000_000_000_000L;
    private static final String ADDRESS_PATTERN = "0x[0-9a-fA-F]{40}";

    public SenseiSamuraWalletProtection(String primaryAddress, long initialBlock) {
        this.state = new SamuraVaultState(primaryAddress, initialBlock);
    }

    public String getPrimaryAddress() {
        return state.getPrimaryAddress();
    }

    public boolean isFrozen() {
        return state.isFrozen();
    }

    public void requestRecovery(String requesterAddress, String newPrimaryAddress, long currentBlock) {
        if (state.isFrozen()) throw new SamuraGuardException(SamuraBladeCodes.SS_VAULT_LOCKED, "Vault frozen");
        if (!state.getGuardianSet().contains(requesterAddress)) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_GUARDIAN, "Not guardian");
        }
        if (state.getRecoveryRequest() != null && !state.getRecoveryRequest().isExecuted()) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_RECOVERY_ACTIVE, "Recovery already requested");
        }
        state.setRecoveryRequest(new SamuraRecoveryRequest(newPrimaryAddress, currentBlock));
    }

    public void executeRecovery(String executorAddress, long currentBlock) {
        if (state.isFrozen()) throw new SamuraGuardException(SamuraBladeCodes.SS_VAULT_LOCKED, "Vault frozen");
        SamuraRecoveryRequest req = state.getRecoveryRequest();
        if (req == null) throw new SamuraGuardException(SamuraBladeCodes.SS_DELAY_NOT_MET, "No recovery requested");
        if (req.isExecuted()) throw new SamuraGuardException(SamuraBladeCodes.SS_ALREADY_SET, "Recovery already executed");
        if (!req.isDelayMet(currentBlock)) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_DELAY_NOT_MET, "Delay not met");
        }
        req.markExecuted();
        state.setPrimaryAddress(req.getNewPrimaryAddress());
    }

    public void addGuardian(String primaryAddress, String guardianAddress) {
        if (!primaryAddress.equals(state.getPrimaryAddress())) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_PRIMARY, "Not primary");
        }
        state.getGuardianSet().add(guardianAddress);
    }

    public void removeGuardian(String primaryAddress, String guardianAddress) {
        if (!primaryAddress.equals(state.getPrimaryAddress())) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_PRIMARY, "Not primary");
        }
        state.getGuardianSet().remove(guardianAddress);
    }

    public void setFrozen(String callerAddress, boolean frozen) {
        boolean isPrimary = callerAddress.equals(state.getPrimaryAddress());
        boolean isGuardian = state.getGuardianSet().contains(callerAddress);
        if (!isPrimary && !isGuardian) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_GUARDIAN, "Not primary or guardian");
        }
        state.setFrozen(frozen);
    }

    public void recordSpend(String primaryAddress, String toAddress, long amountWei, long currentBlock, long timestampMs) {
        if (!primaryAddress.equals(state.getPrimaryAddress())) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_PRIMARY, "Not primary");
        }
        if (state.isFrozen()) throw new SamuraGuardException(SamuraBladeCodes.SS_VAULT_LOCKED, "Vault frozen");
        if (amountWei <= 0 || amountWei > SINGLE_CAP_WEI) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_SINGLE_CAP, "Amount out of single cap");
        }
        SamuraRollingDayWindow w = state.getRollingWindow();
        long spent = w.getRollingSpent(currentBlock);
        if (spent + amountWei > DAILY_CAP_WEI) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_DAILY_CAP, "Daily cap exceeded");
        }
        w.addSpend(toAddress, amountWei, currentBlock, timestampMs);
        state.setCurrentBlockSim(currentBlock);
    }

    public String createSession(String primaryAddress, long nowMs) {
        if (!primaryAddress.equals(state.getPrimaryAddress())) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_NOT_PRIMARY, "Not primary");
        }
        String sessionId = "ss_" + sessionCounter.incrementAndGet() + "_" + System.nanoTime();
        sessions.put(sessionId, new SamuraSession(sessionId, primaryAddress, nowMs));
        return sessionId;
    }

    public boolean validateSession(String sessionId, long nowMs) {
        SamuraSession s = sessions.get(sessionId);
        if (s == null) return false;
        if (s.isExpired(nowMs)) {
            sessions.remove(sessionId);
            return false;
        }
        return true;
    }

    public void invalidateSession(String sessionId) {
        sessions.remove(sessionId);
    }

    public long getRollingSpent(long currentBlock) {
        return state.getRollingWindow().getRollingSpent(currentBlock);
    }

    public boolean isRecoveryReady(long currentBlock) {
        SamuraRecoveryRequest req = state.getRecoveryRequest();
        return req != null && !req.isExecuted() && req.isDelayMet(currentBlock);
    }

    public int getGuardianCount() {
        return state.getGuardianSet().size();
    }

    public static boolean isValidAddressFormat(String addr) {
        return addr != null && Pattern.matches(ADDRESS_PATTERN, addr);
    }

    public static byte[] hashForIntegrity(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(data);
            return md.digest();
        } catch (Exception e) {
            throw new SamuraGuardException(SamuraBladeCodes.SS_BAD_HASH, e.getMessage());
        }
    }

    public static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }

    // --------------- Config / constants access for tests or tooling ---------------
    public static int getBlocksPerDay() { return SamuraSessionConfig.BLOCKS_PER_DAY; }
    public static int getRecoveryDelayBlocks() { return SamuraSessionConfig.RECOVERY_DELAY_BLOCKS; }
    public static int getMaxGuardians() { return SamuraSessionConfig.MAX_GUARDIANS; }
    public static long getDailyCapWei() { return DAILY_CAP_WEI; }
    public static long getSingleCapWei() { return SINGLE_CAP_WEI; }
}

// -----------------------------------------------------------------------------
// VAULT FACTORY (build vault with audit, address book, rate limiter, policy)
// -----------------------------------------------------------------------------

final class SamuraVaultFactory {
    private static final int SEED_BLOCK_OFFSET = 1847;
    private static final int MAX_VAULTS = 501;

    static SenseiSamuraWalletProtection create(String primary, long block) {
        return new SenseiSamuraWalletProtection(primary, block + SEED_BLOCK_OFFSET);
    }
}

// -----------------------------------------------------------------------------
// VALIDATION SUITE (address, amount, hash checks; constants 619, 2847)
// -----------------------------------------------------------------------------

final class SamuraValidationSuite {
    private static final int MIN_ADDR_LEN = 42;
    private static final int MAX_ADDR_LEN = 42;
    private static final long ABS_MIN_WEI = 1L;
    private static final long ABS_MAX_WEI = 10_000_000_000_000_000_000L;
    private static final int HASH_LEN = 32;

    static boolean validateAddress(String addr) {
        if (addr == null) return false;
        if (addr.length() != MAX_ADDR_LEN) return false;
        if (!addr.startsWith("0x")) return false;
        for (int i = 2; i < addr.length(); i++) {
            char c = addr.charAt(i);
            if (!Character.isDigit(c) && (c < 'a' || c > 'f') && (c < 'A' || c > 'F')) return false;
        }
        return true;
