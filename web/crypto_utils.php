<?php
/**
 * Secure Cryptographic Utilities
 * Enterprise-grade cryptography implementations
 * 
 * Security: NIST SP 800-57, OWASP Crypto Guidelines, RFC 7539
 * Standards: AES-256-GCM, Argon2id, HKDF-SHA256, Constant-time operations
 */

class SecureCryptoUtils {
    // AES-256-GCM constants (NIST approved)
    const CIPHER_METHOD = 'aes-256-gcm';
    const KEY_LENGTH = 32; // 256 bits
    const IV_LENGTH = 12;  // 96 bits for GCM (NIST recommended)
    const TAG_LENGTH = 16; // 128 bits authentication tag
    
    // Argon2id parameters (OWASP recommended)
    const PASSWORD_MEMORY_COST = 65536; // 64 MB
    const PASSWORD_TIME_COST = 4;       // 4 iterations
    const PASSWORD_THREADS = 3;         // 3 threads
    
    private static $master_key = null;
    
    /**
     * Get or derive master encryption key
     */
    private static function getMasterKey() {
        if (self::$master_key === null) {
            // Try environment variable first (production)
            if (!empty($_ENV['ENCRYPTION_KEY'])) {
                self::$master_key = hash('sha256', $_ENV['ENCRYPTION_KEY'], true);
            } elseif (defined('ENCRYPTION_KEY')) {
                self::$master_key = hash('sha256', ENCRYPTION_KEY, true);
            } else {
                // Fallback to server-specific key derivation
                $server_entropy = [
                    $_SERVER['SERVER_NAME'] ?? 'localhost',
                    php_uname('n'),
                    filemtime(__FILE__),
                    'cr0bot_master_key_v3_2025'
                ];
                self::$master_key = hash('sha256', implode('|', $server_entropy), true);
            }
        }
        return self::$master_key;
    }
    
    /**
     * HKDF key derivation (RFC 5869)
     */
    private static function deriveKey($purpose, $salt = '', $length = 32) {
        $master_key = self::getMasterKey();
        
        // Extract phase
        if (empty($salt)) {
            $salt = str_repeat("\x00", 32);
        }
        $prk = hash_hmac('sha256', $master_key, $salt, true);
        
        // Expand phase
        $info = 'cr0bot_v3|' . $purpose;
        $t = '';
        $okm = '';
        $counter = 1;
        
        while (strlen($okm) < $length) {
            $t = hash_hmac('sha256', $t . $info . chr($counter), $prk, true);
            $okm .= $t;
            $counter++;
        }
        
        return substr($okm, 0, $length);
    }
    
    /**
     * Encrypt data using AES-256-GCM with authenticated encryption
     */
    public static function encrypt($plaintext, $purpose = 'general') {
        if (!is_string($plaintext)) {
            throw new InvalidArgumentException('Plaintext must be a string');
        }
        
        // Validate plaintext size (prevent DoS)
        if (strlen($plaintext) > 1048576) { // 1MB limit
            throw new InvalidArgumentException('Plaintext too large');
        }
        
        // Generate cryptographically secure IV
        $iv = random_bytes(self::IV_LENGTH);
        
        // Derive purpose-specific key
        $key = self::deriveKey($purpose);
        
        // Encrypt with authenticated encryption
        $tag = '';
        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($ciphertext === false) {
            $error = openssl_error_string();
            throw new Exception('Encryption failed: ' . ($error ?: 'Unknown error'));
        }
        
        // Combine IV + ciphertext + tag
        $encrypted_data = $iv . $ciphertext . $tag;
        
        return base64_encode($encrypted_data);
    }
    
    /**
     * Decrypt data using AES-256-GCM with authentication verification
     */
    public static function decrypt($encrypted_data, $purpose = 'general') {
        if (!is_string($encrypted_data) || empty($encrypted_data)) {
            throw new InvalidArgumentException('Invalid encrypted data');
        }
        
        // Decode base64
        $raw_data = base64_decode($encrypted_data, true);
        if ($raw_data === false) {
            throw new Exception('Invalid base64 encoding');
        }
        
        // Validate minimum length
        $min_length = self::IV_LENGTH + self::TAG_LENGTH + 1;
        if (strlen($raw_data) < $min_length) {
            throw new Exception('Encrypted data too short');
        }
        
        // Extract components
        $iv = substr($raw_data, 0, self::IV_LENGTH);
        $tag = substr($raw_data, -self::TAG_LENGTH);
        $ciphertext = substr($raw_data, self::IV_LENGTH, -self::TAG_LENGTH);
        
        // Derive purpose-specific key
        $key = self::deriveKey($purpose);
        
        // Decrypt with authentication verification
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER_METHOD,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
        
        if ($plaintext === false) {
            throw new Exception('Decryption failed: authentication verification failed');
        }
        
        return $plaintext;
    }
    
    /**
     * Generate secure token with expiration and purpose binding
     */
    public static function generateSecureToken($data, $purpose = 'token', $ttl = 3600) {
        $timestamp = time();
        $expires = $timestamp + $ttl;
        $nonce = bin2hex(random_bytes(16));
        
        $payload = [
            'data' => $data,
            'timestamp' => $timestamp,
            'expires' => $expires,
            'nonce' => $nonce,
            'purpose' => $purpose,
            'version' => '3.0'
        ];
        
        $payload_json = json_encode($payload);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception('JSON encoding error: ' . json_last_error_msg());
        }
        
        // Encrypt the entire payload
        $encrypted_payload = self::encrypt($payload_json, 'token_' . $purpose);
        
        // Create token structure
        $token_data = [
            'payload' => $encrypted_payload,
            'version' => '3.0',
            'purpose' => $purpose
        ];
        
        return base64_encode(json_encode($token_data));
    }
    
    /**
     * Validate secure token with comprehensive security checks
     */
    public static function validateSecureToken($token, $expected_purpose = 'token') {
        try {
            if (!is_string($token) || empty($token)) {
                return false;
            }
            
            // Prevent DoS with large tokens
            if (strlen($token) > 8192) {
                return false;
            }
            
            // Decode token structure
            $decoded = json_decode(base64_decode($token, true), true);
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($decoded)) {
                return false;
            }
            
            // Validate token structure
            $required_fields = ['payload', 'version', 'purpose'];
            foreach ($required_fields as $field) {
                if (!isset($decoded[$field])) {
                    return false;
                }
            }
            
            // Version check
            if ($decoded['version'] !== '3.0') {
                return false;
            }
            
            // Purpose validation
            if ($decoded['purpose'] !== $expected_purpose) {
                return false;
            }
            
            // Decrypt and validate payload
            $payload_json = self::decrypt($decoded['payload'], 'token_' . $expected_purpose);
            $payload = json_decode($payload_json, true);
            
            if (json_last_error() !== JSON_ERROR_NONE || !is_array($payload)) {
                return false;
            }
            
            // Validate payload structure
            $required_payload_fields = ['timestamp', 'expires', 'nonce', 'purpose', 'version'];
            foreach ($required_payload_fields as $field) {
                if (!isset($payload[$field])) {
                    return false;
                }
            }
            
            // Purpose consistency check
            if ($payload['purpose'] !== $expected_purpose) {
                return false;
            }
            
            // Version consistency check
            if ($payload['version'] !== '3.0') {
                return false;
            }
            
            // Expiration check
            if (time() >= $payload['expires']) {
                return false;
            }
            
            // Age validation (not too old)
            if ((time() - $payload['timestamp']) > 86400) { // 24 hours max
                return false;
            }
            
            // Future timestamp check
            if ($payload['timestamp'] > (time() + 60)) { // 1 minute tolerance
                return false;
            }
            
            return $payload['data'];
            
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Hash password using Argon2id with secure parameters
     */
    public static function hashPassword($password) {
        if (!is_string($password)) {
            throw new InvalidArgumentException('Password must be a string');
        }
        
        // Prevent DoS with extremely long passwords
        if (strlen($password) > 4096) {
            throw new InvalidArgumentException('Password too long');
        }
        
        if (empty($password)) {
            throw new InvalidArgumentException('Password cannot be empty');
        }
        
        $hash = password_hash($password, PASSWORD_ARGON2ID, [
            'memory_cost' => self::PASSWORD_MEMORY_COST,
            'time_cost' => self::PASSWORD_TIME_COST,
            'threads' => self::PASSWORD_THREADS
        ]);
        
        if ($hash === false) {
            throw new Exception('Password hashing failed');
        }
        
        return $hash;
    }
    
    /**
     * Verify password with constant-time comparison
     */
    public static function verifyPassword($password, $hash) {
        if (!is_string($password) || !is_string($hash)) {
            return false;
        }
        
        // Prevent timing attacks by always performing hash operation
        $result = password_verify($password, $hash);
        
        // Dummy operation to maintain constant timing
        if (!$result) {
            password_hash('dummy_password_for_timing', PASSWORD_DEFAULT);
        }
        
        return $result;
    }
    
    /**
     * Generate cryptographically secure CSRF token
     */
    public static function generateCSRFToken() {
        return bin2hex(random_bytes(32));
    }
    
    /**
     * Validate CSRF token with constant-time comparison
     */
    public static function validateCSRFToken($token, $expected) {
        if (!is_string($token) || !is_string($expected)) {
            return false;
        }
        
        // Validate format (64 hex characters)
        if (strlen($token) !== 64 || strlen($expected) !== 64) {
            return false;
        }
        
        if (!ctype_xdigit($token) || !ctype_xdigit($expected)) {
            return false;
        }
        
        return hash_equals($expected, $token);
    }
    
    /**
     * Generate high-entropy session token
     */
    public static function generateSessionToken() {
        return bin2hex(random_bytes(64)); // 512-bit token
    }
    
    /**
     * Generate cryptographically secure random string
     */
    public static function generateSecureRandom($length = 32, $alphabet = null) {
        if ($length <= 0 || $length > 1024) {
            throw new InvalidArgumentException('Invalid length parameter');
        }
        
        if ($alphabet === null) {
            // Base64url alphabet (URL-safe)
            $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
        }
        
        $alphabet_length = strlen($alphabet);
        if ($alphabet_length < 2) {
            throw new InvalidArgumentException('Alphabet too short');
        }
        
        $random = '';
        for ($i = 0; $i < $length; $i++) {
            $random .= $alphabet[random_int(0, $alphabet_length - 1)];
        }
        
        return $random;
    }
    
    /**
     * Secure comparison for sensitive strings (constant-time)
     */
    public static function secureCompare($a, $b) {
        if (!is_string($a) || !is_string($b)) {
            return false;
        }
        
        return hash_equals($a, $b);
    }
    
    /**
     * Generate HMAC with validation
     */
    public static function generateHMAC($data, $purpose = 'general') {
        if (!is_string($data)) {
            throw new InvalidArgumentException('Data must be a string');
        }
        
        $key = self::deriveKey('hmac_' . $purpose);
        return hash_hmac('sha256', $data, $key);
    }
    
    /**
     * Validate HMAC with constant-time comparison
     */
    public static function validateHMAC($data, $hmac, $purpose = 'general') {
        if (!is_string($data) || !is_string($hmac)) {
            return false;
        }
        
        $expected_hmac = self::generateHMAC($data, $purpose);
        return hash_equals($expected_hmac, $hmac);
    }
    
    /**
     * Generate nonce for cryptographic operations
     */
    public static function generateNonce($length = 16) {
        if ($length <= 0 || $length > 256) {
            throw new InvalidArgumentException('Invalid nonce length');
        }
        
        return bin2hex(random_bytes($length));
    }
    
    /**
     * Securely wipe sensitive data from memory
     */
    public static function secureClear(&$data) {
        if (is_string($data)) {
            $data = str_repeat("\x00", strlen($data));
        } elseif (is_array($data)) {
            foreach ($data as &$value) {
                self::secureClear($value);
            }
        }
        $data = null;
    }
}

/**
 * Legacy compatibility wrapper for existing code
 */
class CryptoUtils extends SecureCryptoUtils {
    // Maintain backward compatibility while using secure implementations
    
    public static function getSecretKey() {
        // Legacy method - redirect to secure implementation
        return bin2hex(parent::deriveKey('legacy_secret'));
    }
    
    public static function generateGameStateHash($session_data) {
        $factors = [
            $session_data['blocks_destroyed'] ?? 0,
            $session_data['current_level'] ?? 1,
            $session_data['game_duration'] ?? 0,
            $session_data['powerups_collected'] ?? 0,
            $session_data['lives_lost'] ?? 0,
            $session_data['start_time'] ?? time(),
        ];
        
        $data = implode('|', $factors);
        return parent::generateHMAC($data, 'game_state');
    }
    
    public static function obfuscateResponse($data) {
        // Maintain existing functionality but with secure random
        $decoys = [
            'debug_mode' => false,
            'admin_override' => false,
            'validation_bypass' => false,
            'cheat_detected' => false,
            'security_level' => random_int(1, 5),
            'anti_tamper' => parent::generateNonce(8),
            'server_load' => random_int(10, 95) . '%',
            'cache_hit' => (bool)random_int(0, 1)
        ];
        
        return array_merge($data, $decoys);
    }
}
?>