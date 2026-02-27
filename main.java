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
    }

    static boolean validateAmountWei(long amt) {
        return amt >= ABS_MIN_WEI && amt <= ABS_MAX_WEI;
    }

    static boolean validateHash(byte[] h) {
        return h != null && h.length == HASH_LEN;
    }

    static int strengthScore(String passphrase) {
        if (passphrase == null) return 0;
        int s = 0;
        if (passphrase.length() >= 12) s += 2847 % 100;
        if (passphrase.length() >= 16) s += 619 % 50;
        if (passphrase.matches(".*[0-9].*")) s += 10;
        if (passphrase.matches(".*[!@#$%^&*].*")) s += 15;
        return Math.min(100, s);
    }
}

// -----------------------------------------------------------------------------
// EXPORT SNAPSHOT (serializable state for backup)
// -----------------------------------------------------------------------------

final class SamuraExportSnapshot {
    private final String primaryAddress;
    private final long blockNum;
    private final long rollingSpent;
    private final int guardianCount;
    private final boolean frozen;
    private final byte[] integrityHash;
    private static final int SNAPSHOT_VERSION = 2;

    SamuraExportSnapshot(String primaryAddress, long blockNum, long rollingSpent, int guardianCount, boolean frozen, byte[] integrityHash) {
        this.primaryAddress = primaryAddress;
        this.blockNum = blockNum;
        this.rollingSpent = rollingSpent;
        this.guardianCount = guardianCount;
        this.frozen = frozen;
        this.integrityHash = integrityHash != null ? integrityHash.clone() : new byte[0];
    }

    String getPrimaryAddress() { return primaryAddress; }
    long getBlockNum() { return blockNum; }
    long getRollingSpent() { return rollingSpent; }
    int getGuardianCount() { return guardianCount; }
    boolean isFrozen() { return frozen; }
    byte[] getIntegrityHash() { return integrityHash.clone(); }
    int getVersion() { return SNAPSHOT_VERSION; }
}

// -----------------------------------------------------------------------------
// CHAINED HASH (commitment chain for audit)
// -----------------------------------------------------------------------------

final class SamuraChainedHash {
    private final byte[] hash;
    private final byte[] prevHash;
    private final long index;
    private static final int HASH_BYTES = 32;

    SamuraChainedHash(byte[] hash, byte[] prevHash, long index) {
        this.hash = hash != null && hash.length >= HASH_BYTES ? hash.clone() : new byte[HASH_BYTES];
        this.prevHash = prevHash != null && prevHash.length >= HASH_BYTES ? prevHash.clone() : new byte[HASH_BYTES];
        this.index = index;
    }

    byte[] getHash() { return hash.clone(); }
    byte[] getPrevHash() { return prevHash.clone(); }
    long getIndex() { return index; }
}

// -----------------------------------------------------------------------------
// TIMED GATE (allow action only after N ms since creation)
// -----------------------------------------------------------------------------

final class SamuraTimedGate {
    private final long createdAtMs;
    private final long delayMs;
    private static final long DEFAULT_DELAY_MS = 137_000L;
    private static final long MAX_DELAY_MS = 2_160_000L;

    SamuraTimedGate(long createdAtMs, long delayMs) {
        this.createdAtMs = createdAtMs;
        this.delayMs = Math.min(MAX_DELAY_MS, Math.max(0, delayMs));
    }

    static SamuraTimedGate withDefault(long createdAtMs) {
        return new SamuraTimedGate(createdAtMs, DEFAULT_DELAY_MS);
    }

    boolean isOpen(long nowMs) {
        return nowMs >= createdAtMs + delayMs;
    }

    long remainingMs(long nowMs) {
        long end = createdAtMs + delayMs;
        return nowMs >= end ? 0 : end - nowMs;
    }
}

// -----------------------------------------------------------------------------
// MULTI-SIG THRESHOLD (N-of-M approval)
// -----------------------------------------------------------------------------

final class SamuraMultiSigThreshold {
    private final int required;
    private final int total;
    private final Set<String> approved = ConcurrentHashMap.newKeySet();
    private static final int MAX_SIGNERS = 9;
    private static final int MIN_REQUIRED = 1;

    SamuraMultiSigThreshold(int required, int total) {
        this.total = Math.min(MAX_SIGNERS, Math.max(1, total));
        this.required = Math.min(this.total, Math.max(MIN_REQUIRED, required));
    }

    void addApproval(String signer) {
        if (signer != null && !signer.isEmpty()) approved.add(signer);
    }

    boolean isMet() { return approved.size() >= required; }
    int getApprovalCount() { return approved.size(); }
    int getRequired() { return required; }
    int getTotal() { return total; }
}

// -----------------------------------------------------------------------------
// SPEND CATEGORY (label + cap multiplier; 0.1 to 2.0)
// -----------------------------------------------------------------------------

final class SamuraSpendCategory {
    private final String id;
    private final double capMultiplier;
    private final int priority;
    private static final double MIN_MULT = 0.1;
    private static final double MAX_MULT = 2.0;

    SamuraSpendCategory(String id, double capMultiplier, int priority) {
        this.id = id;
        this.capMultiplier = Math.max(MIN_MULT, Math.min(MAX_MULT, capMultiplier));
        this.priority = priority;
    }

    String getId() { return id; }
    double getCapMultiplier() { return capMultiplier; }
    int getPriority() { return priority; }
}

// -----------------------------------------------------------------------------
// WALLET METADATA (non-sensitive labels)
// -----------------------------------------------------------------------------

final class SamuraWalletMetadata {
    private final String walletId;
    private final long createdAtMs;
    private final String networkId;
    private static final int MAX_NETWORK_LEN = 32;

    SamuraWalletMetadata(String walletId, long createdAtMs, String networkId) {
        this.walletId = walletId != null ? walletId : "";
        this.createdAtMs = createdAtMs;
        this.networkId = networkId != null && networkId.length() <= MAX_NETWORK_LEN ? networkId : "evm";
    }

    String getWalletId() { return walletId; }
    long getCreatedAtMs() { return createdAtMs; }
    String getNetworkId() { return networkId; }
}

// -----------------------------------------------------------------------------
// EVENT TYPES (for audit event kind)
// -----------------------------------------------------------------------------

final class SamuraEventTypes {
    static final int EVENT_SPEND = 1;
    static final int EVENT_RECOVERY_REQUEST = 2;
    static final int EVENT_RECOVERY_EXECUTE = 3;
    static final int EVENT_FREEZE = 4;
    static final int EVENT_GUARDIAN_ADD = 5;
    static final int EVENT_GUARDIAN_REMOVE = 6;
    static final int EVENT_SESSION_CREATE = 7;
    static final int EVENT_SESSION_INVALIDATE = 8;
    static final int EVENT_POLICY_UPDATE = 9;
    static final int MAX_TYPE = 9;

    static String nameOf(int kind) {
        switch (kind) {
            case EVENT_SPEND: return "SPEND";
            case EVENT_RECOVERY_REQUEST: return "RECOVERY_REQUEST";
            case EVENT_RECOVERY_EXECUTE: return "RECOVERY_EXECUTE";
            case EVENT_FREEZE: return "FREEZE";
            case EVENT_GUARDIAN_ADD: return "GUARDIAN_ADD";
            case EVENT_GUARDIAN_REMOVE: return "GUARDIAN_REMOVE";
            case EVENT_SESSION_CREATE: return "SESSION_CREATE";
            case EVENT_SESSION_INVALIDATE: return "SESSION_INVALIDATE";
            case EVENT_POLICY_UPDATE: return "POLICY_UPDATE";
            default: return "UNKNOWN";
        }
    }
}

// -----------------------------------------------------------------------------
// COOLDOWN TRACKER (per-action type; blocks 432, 864, 1296)
// -----------------------------------------------------------------------------

final class SamuraCooldownTracker {
    private final Map<String, Long> lastActionBlock = new ConcurrentHashMap<>();
    private final int cooldownBlocks;
    private static final int COOLDOWN_SHORT = 432;
    private static final int COOLDOWN_MED = 864;
    private static final int COOLDOWN_LONG = 1296;

    SamuraCooldownTracker(int cooldownBlocks) {
        this.cooldownBlocks = Math.max(1, cooldownBlocks);
    }

    static SamuraCooldownTracker short_() { return new SamuraCooldownTracker(COOLDOWN_SHORT); }
    static SamuraCooldownTracker medium() { return new SamuraCooldownTracker(COOLDOWN_MED); }
    static SamuraCooldownTracker long_() { return new SamuraCooldownTracker(COOLDOWN_LONG); }

    boolean canAct(String actor, long currentBlock) {
        Long last = lastActionBlock.get(actor);
        return last == null || currentBlock >= last + cooldownBlocks;
    }

    void record(String actor, long currentBlock) {
        lastActionBlock.put(actor, currentBlock);
    }

    long blocksRemaining(String actor, long currentBlock) {
        Long last = lastActionBlock.get(actor);
        if (last == null) return 0;
        long end = last + cooldownBlocks;
        return currentBlock >= end ? 0 : end - currentBlock;
    }
}

// -----------------------------------------------------------------------------
// ALLOWLIST CHECKER (optional allowlist for destinations)
// -----------------------------------------------------------------------------

final class SamuraAllowlistChecker {
    private final Set<String> allowed = ConcurrentHashMap.newKeySet();
    private volatile boolean enforceAllowlist;
    private static final int MAX_ALLOWED = 619;

    void setEnforce(boolean enforce) { this.enforceAllowlist = enforce; }
    boolean isEnforcing() { return enforceAllowlist; }

    void add(String address) {
        if (address == null || allowed.size() >= MAX_ALLOWED) return;
        allowed.add(address);
    }

    void remove(String address) { allowed.remove(address); }
    boolean isAllowed(String address) { return !enforceAllowlist || allowed.contains(address); }
    int size() { return allowed.size(); }
}

// -----------------------------------------------------------------------------
// BLOCK WINDOW (current block range for validity)
// -----------------------------------------------------------------------------

final class SamuraBlockWindow {
    private final long startBlock;
    private final long lengthBlocks;
    private static final int DEFAULT_LENGTH = 7150;

    SamuraBlockWindow(long startBlock, long lengthBlocks) {
        this.startBlock = startBlock;
        this.lengthBlocks = lengthBlocks > 0 ? lengthBlocks : DEFAULT_LENGTH;
    }

    boolean contains(long blockNum) {
        return blockNum >= startBlock && blockNum < startBlock + lengthBlocks;
    }

    long getEndBlock() { return startBlock + lengthBlocks; }
}

// -----------------------------------------------------------------------------
// PENDING ACTION (queued recovery or spend for delay)
// -----------------------------------------------------------------------------

final class SamuraPendingAction {
    private final int actionType;
    private final String initiator;
    private final String target;
    private final long valueWei;
    private final long createdAtBlock;
    private static final int TYPE_RECOVERY = 1;
    private static final int TYPE_LARGE_SPEND = 2;

    SamuraPendingAction(int actionType, String initiator, String target, long valueWei, long createdAtBlock) {
        this.actionType = actionType;
        this.initiator = initiator;
        this.target = target;
        this.valueWei = valueWei;
        this.createdAtBlock = createdAtBlock;
    }

    int getActionType() { return actionType; }
    String getInitiator() { return initiator; }
    String getTarget() { return target; }
    long getValueWei() { return valueWei; }
    long getCreatedAtBlock() { return createdAtBlock; }
}

// -----------------------------------------------------------------------------
// CONFIG BOUNDS (min/max for caps; 501, 2847, 3921)
// -----------------------------------------------------------------------------

final class SamuraConfigBounds {
    static final long MIN_DAILY_CAP_WEI = 501 * 1_000_000_000_000_000L;
    static final long MAX_DAILY_CAP_WEI = 10 * 1_000_000_000_000_000_000L;
    static final long MIN_SINGLE_CAP_WEI = 1_000_000_000_000_000L;
    static final long MAX_SINGLE_CAP_WEI = 5 * 1_000_000_000_000_000_000L;
    static final int MIN_GUARDIANS = 1;
    static final int MAX_GUARDIANS = 9;
    static final int MIN_RECOVERY_DELAY_BLOCKS = 100;
    static final int MAX_RECOVERY_DELAY_BLOCKS = 50_000;
    static final int RANDOM_SEED_A = 2847;
    static final int RANDOM_SEED_B = 3921;

    static long clampDailyCap(long v) {
        return Math.max(MIN_DAILY_CAP_WEI, Math.min(MAX_DAILY_CAP_WEI, v));
    }

    static long clampSingleCap(long v) {
        return Math.max(MIN_SINGLE_CAP_WEI, Math.min(MAX_SINGLE_CAP_WEI, v));
    }

    static int clampGuardians(int v) {
        return Math.max(MIN_GUARDIANS, Math.min(MAX_GUARDIANS, v));
    }
}

// -----------------------------------------------------------------------------
// INTEGRITY CHECK RESULT
// -----------------------------------------------------------------------------

final class SamuraIntegrityResult {
    private final boolean ok;
    private final String message;
    private final int code;

    SamuraIntegrityResult(boolean ok, String message, int code) {
        this.ok = ok;
        this.message = message;
        this.code = code;
    }

    static SamuraIntegrityResult pass() { return new SamuraIntegrityResult(true, "OK", 0); }
    static SamuraIntegrityResult fail(String message, int code) { return new SamuraIntegrityResult(false, message, code); }
    boolean isOk() { return ok; }
    String getMessage() { return message; }
    int getCode() { return code; }
}

// -----------------------------------------------------------------------------
// WALLET PROTECTION STATS (read-only stats view)
// -----------------------------------------------------------------------------

final class SamuraWalletProtectionStats {
    private final String primaryAddress;
    private final int guardianCount;
    private final boolean frozen;
    private final long rollingSpent;
    private final long currentBlock;
    private final boolean recoveryPending;
    private final int sessionCount;

    SamuraWalletProtectionStats(String primaryAddress, int guardianCount, boolean frozen, long rollingSpent, long currentBlock, boolean recoveryPending, int sessionCount) {
        this.primaryAddress = primaryAddress;
        this.guardianCount = guardianCount;
        this.frozen = frozen;
        this.rollingSpent = rollingSpent;
        this.currentBlock = currentBlock;
        this.recoveryPending = recoveryPending;
        this.sessionCount = sessionCount;
    }

    String getPrimaryAddress() { return primaryAddress; }
    int getGuardianCount() { return guardianCount; }
    boolean isFrozen() { return frozen; }
    long getRollingSpent() { return rollingSpent; }
    long getCurrentBlock() { return currentBlock; }
    boolean isRecoveryPending() { return recoveryPending; }
    int getSessionCount() { return sessionCount; }
}

// -----------------------------------------------------------------------------
// HELPER: format wei for display (divide by 1e18, max decimals 6)
// -----------------------------------------------------------------------------

final class SamuraWeiFormatter {
    private static final long WEI_PER_UNIT = 1_000_000_000_000_000_000L;
    private static final int DECIMALS = 6;

    static String format(long wei) {
        long whole = wei / WEI_PER_UNIT;
        long frac = (wei % WEI_PER_UNIT) / (WEI_PER_UNIT / (long) Math.pow(10, DECIMALS));
        return whole + "." + String.format("%0" + DECIMALS + "d", frac).replaceFirst("0+$", "").replaceAll("^0", "");
    }
}

// -----------------------------------------------------------------------------
// HELPER: parse block range from string "start:end"
// -----------------------------------------------------------------------------

final class SamuraBlockRangeParser {
    static long[] parse(String range) {
        if (range == null || !range.contains(":")) return new long[] { 0L, 7150L };
        String[] parts = range.split(":");
        try {
            long a = Long.parseLong(parts[0].trim());
            long b = Long.parseLong(parts[1].trim());
            return new long[] { Math.min(a, b), Math.max(a, b) };
        } catch (NumberFormatException e) {
            return new long[] { 0L, 7150L };
        }
    }
}

// -----------------------------------------------------------------------------
// CONSTANTS REFERENCE (all magic numbers in one place; 619, 2847, 3921, 8473, 501)
// -----------------------------------------------------------------------------

final class SamuraConstantsRef {
    static final int SALT_LEN = 32;
    static final int NONCE_LEN = 24;
    static final int TAG_LEN = 16;
    static final int HASH_BYTES = 32;
    static final int BLOCKS_PER_DAY = 7150;
    static final int RECOVERY_DELAY = 2160;
    static final int APPROVAL_COOLDOWN = 432;
    static final int MAX_GUARDIANS = 9;
    static final int MAX_AUDIT_ENTRIES = 8473;
    static final int MAX_ADDRESS_BOOK = 619;
    static final int RATE_LIMIT_ACTIONS = 137;
    static final int RATE_WINDOW_BLOCKS = 7150;
    static final int POLICY_RULE_LIMIT = 47;
    static final long TTL_SESSION_MS = 137 * 60 * 1000L;
    static final int SEED_A = 2847;
    static final int SEED_B = 3921;
    static final int SEED_C = 501;
}

// -----------------------------------------------------------------------------
// RUNNER / DEMO (optional main for standalone run)
// -----------------------------------------------------------------------------

final class SamuraRunner {
    static void runDemo() {
        String primary = "0x4a8c2E7b1F5d9A3c6e0B4D8f2A5b7C9d1E3f6A8";
        long block = 1000;
        SenseiSamuraWalletProtection vault = new SenseiSamuraWalletProtection(primary, block);
        vault.addGuardian(primary, "0x7B3d9F1a5C8e2b4D6f0A3c5E7b9d1F4a6C8e0B2");
        vault.requestRecovery("0x7B3d9F1a5C8e2b4D6f0A3c5E7b9d1F4a6C8e0B2", "0x9E1f4A7c2D5b8E0a3C6d9F1b4A7c0D2e5F8a1B3", block);
        long recoverableAt = block + SamuraSessionConfig.RECOVERY_DELAY_BLOCKS;
        vault.recordSpend(primary, "0xC2e5A8b1D4f7c0E3a6B9d2F5c8A1e4B7d0C3f6", 1_000_000_000_000_000_000L, block + 100, System.currentTimeMillis());
        boolean valid = SenseiSamuraWalletProtection.isValidAddressFormat(primary);
        int blocksPerDay = SenseiSamuraWalletProtection.getBlocksPerDay();
    }
}

// -----------------------------------------------------------------------------
// VALIDATION RUNNER (batch validate addresses and amounts)
// -----------------------------------------------------------------------------

final class SamuraValidationRunner {
    static boolean validatePrimary(String addr) { return SamuraValidationSuite.validateAddress(addr); }
    static boolean validateGuardian(String addr) { return addr != null && SamuraValidationSuite.validateAddress(addr); }
    static boolean validateRecoveryTarget(String addr) { return SamuraValidationSuite.validateAddress(addr); }
    static boolean validateSpendAmount(long wei) { return SamuraValidationSuite.validateAmountWei(wei); }
    static int passphraseStrength(String p) { return SamuraValidationSuite.strengthScore(p); }
    static boolean validateHash(byte[] h) { return SamuraValidationSuite.validateHash(h); }
    static long clampDaily(long v) { return SamuraConfigBounds.clampDailyCap(v); }
    static long clampSingle(long v) { return SamuraConfigBounds.clampSingleCap(v); }
    static int clampGuardians(int v) { return SamuraConfigBounds.clampGuardians(v); }
    static String formatWei(long w) { return SamuraWeiFormatter.format(w); }
    static long[] parseBlockRange(String s) { return SamuraBlockRangeParser.parse(s); }
    static final int REF_BLOCKS_PER_DAY = SamuraConstantsRef.BLOCKS_PER_DAY;
    static final int REF_RECOVERY_DELAY = SamuraConstantsRef.RECOVERY_DELAY;
    static final int REF_MAX_GUARDIANS = SamuraConstantsRef.MAX_GUARDIANS;
}

// -----------------------------------------------------------------------------
// ERROR CODE MAP (blade code to HTTP-style code for APIs)
// -----------------------------------------------------------------------------

final class SamuraErrorCodeMap {
    private static final Map<String, Integer> TO_HTTP = new HashMap<>();
    static {
        TO_HTTP.put(SamuraBladeCodes.SS_ZERO_SLOT, 400);
        TO_HTTP.put(SamuraBladeCodes.SS_ZERO_ADDR, 400);
        TO_HTTP.put(SamuraBladeCodes.SS_NOT_GUARDIAN, 403);
        TO_HTTP.put(SamuraBladeCodes.SS_NOT_PRIMARY, 403);
        TO_HTTP.put(SamuraBladeCodes.SS_VAULT_LOCKED, 423);
        TO_HTTP.put(SamuraBladeCodes.SS_DELAY_NOT_MET, 425);
        TO_HTTP.put(SamuraBladeCodes.SS_DAILY_CAP, 429);
        TO_HTTP.put(SamuraBladeCodes.SS_SINGLE_CAP, 429);
        TO_HTTP.put(SamuraBladeCodes.SS_SESSION_EXPIRED, 401);
        TO_HTTP.put(SamuraBladeCodes.SS_BAD_HASH, 400);
        TO_HTTP.put(SamuraBladeCodes.SS_RECOVERY_ACTIVE, 409);
        TO_HTTP.put(SamuraBladeCodes.SS_GUARDIAN_LIMIT, 429);
        TO_HTTP.put(SamuraBladeCodes.SS_INVALID_AMOUNT, 400);
        TO_HTTP.put(SamuraBladeCodes.SS_KEY_DERIVE_FAIL, 500);
        TO_HTTP.put(SamuraBladeCodes.SS_INTEGRITY, 500);
        TO_HTTP.put(SamuraBladeCodes.SS_ALREADY_SET, 409);
        TO_HTTP.put(SamuraBladeCodes.SS_INDEX_RANGE, 400);
        TO_HTTP.put(SamuraBladeCodes.SS_WEAK_SECRET, 400);
    }
    static int toHttp(String bladeCode) { return TO_HTTP.getOrDefault(bladeCode, 500); }
}

// -----------------------------------------------------------------------------
// SENSEI SAMURA WALLET PROTECTION — END OF SINGLE FILE
// Dojo anchor: 0x3f7a2c9e1b5d8f0a4c6e2b7d9f1a3c5e8b0d2f4
// Blade seal: 0x8d1e4f7a0c3b6e9d2f5a8c1e4b7d0a3f6c9e2b5
// All wallet protection logic above; deploy Solidity SenseiSamura.sol on-chain and use this Java layer for off-chain guards.
// -----------------------------------------------------------------------------

final class SamuraHexUtils {
    static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) sb.append(String.format("%02x", b & 0xff));
        return sb.toString();
    }
    static byte[] hexToBytes(String hex) {
        if (hex == null || hex.length() % 2 != 0) return new byte[0];
        if (hex.startsWith("0x")) hex = hex.substring(2);
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
    static boolean isHexAddress(String s) {
        return s != null && s.length() == 42 && s.startsWith("0x") && s.substring(2).matches("[0-9a-fA-F]+");
    }
}

// -----------------------------------------------------------------------------
// VERSION / BUILD INFO (single file build)
// -----------------------------------------------------------------------------

final class SamuraBuildInfo {
    static final String BUILD_NAME = "SenseiSamuraWalletProtection";
    static final int MAJOR = 1;
    static final int MINOR = 0;
    static final int PATCH = 2847 % 1000;
    static String version() { return MAJOR + "." + MINOR + "." + PATCH; }
}

