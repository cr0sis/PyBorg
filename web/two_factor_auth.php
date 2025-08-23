<?php
/**
 * Two-Factor Authentication System
 * TOTP (Time-based One-Time Password) implementation
 */

class TwoFactorAuth {
    private static $secret_length = 32;
    
    /**
     * Get database connection with timeout and retry logic
     */
    private static function getDatabaseConnection($max_retries = 3, $timeout = 30) {
        require_once 'config_paths.php';
        $attempt = 0;
        while ($attempt < $max_retries) {
            try {
                $pdo = new PDO("sqlite:" . ConfigPaths::getDatabase('users'));
                $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $pdo->setAttribute(PDO::ATTR_TIMEOUT, $timeout);
                $pdo->exec("PRAGMA busy_timeout = " . ($timeout * 1000));
                $pdo->exec("PRAGMA journal_mode = WAL");
                return $pdo;
            } catch (Exception $e) {
                $attempt++;
                error_log("2FA DB connection attempt $attempt failed: " . $e->getMessage());
                if ($attempt < $max_retries) {
                    usleep(100000 * $attempt);
                }
            }
        }
        throw new Exception("Failed to connect to 2FA database after $max_retries attempts");
    }
    
    /**
     * Generate a new secret key for 2FA setup
     */
    public static function generateSecret() {
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $secret = '';
        for ($i = 0; $i < self::$secret_length; $i++) {
            $secret .= $chars[random_int(0, strlen($chars) - 1)];
        }
        return $secret;
    }
    
    /**
     * Generate current TOTP code
     */
    public static function generateTOTP($secret, $timestamp = null) {
        if ($timestamp === null) {
            $timestamp = time();
        }
        
        // Convert secret from base32
        $key = self::base32Decode($secret);
        
        // Calculate time window (30 second intervals)
        $time = floor($timestamp / 30);
        
        // Pack time as 64-bit big-endian
        $timeBytes = pack('N*', 0) . pack('N*', $time);
        
        // HMAC-SHA1
        $hash = hash_hmac('sha1', $timeBytes, $key, true);
        
        // Dynamic truncation
        $offset = ord($hash[19]) & 0xf;
        $code = (
            ((ord($hash[$offset]) & 0x7f) << 24) |
            ((ord($hash[$offset + 1]) & 0xff) << 16) |
            ((ord($hash[$offset + 2]) & 0xff) << 8) |
            (ord($hash[$offset + 3]) & 0xff)
        ) % 1000000;
        
        return sprintf('%06d', $code);
    }
    
    /**
     * Verify TOTP code (allows 1 window tolerance)
     */
    public static function verifyTOTP($secret, $code, $tolerance = 1) {
        $timestamp = time();
        
        for ($i = -$tolerance; $i <= $tolerance; $i++) {
            $testTime = $timestamp + ($i * 30);
            $validCode = self::generateTOTP($secret, $testTime);
            
            if (hash_equals($validCode, $code)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Generate QR code URL for Google Authenticator
     */
    public static function getQRCodeURL($secret, $issuer, $accountName) {
        $url = 'otpauth://totp/' . urlencode($issuer . ':' . $accountName) 
             . '?secret=' . $secret 
             . '&issuer=' . urlencode($issuer)
             . '&algorithm=SHA1'
             . '&digits=6'
             . '&period=30';
        
        return 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&ecc=M&data=' . urlencode($url);
    }
    
    /**
     * Get the raw OTPAUTH URL (for manual entry or debugging)
     */
    public static function getOTPAuthURL($secret, $issuer, $accountName) {
        return 'otpauth://totp/' . urlencode($issuer . ':' . $accountName) 
             . '?secret=' . $secret 
             . '&issuer=' . urlencode($issuer)
             . '&algorithm=SHA1'
             . '&digits=6'
             . '&period=30';
    }
    
    /**
     * Enable 2FA for a user
     */
    public static function enableForUser($user_id, $secret) {
        try {
            require_once 'config_paths.php';
            $db_path = ConfigPaths::getDatabase('users');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            // Add 2FA columns if they don't exist
            try {
                $pdo->exec("ALTER TABLE users ADD COLUMN totp_secret TEXT DEFAULT NULL");
                $pdo->exec("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0");
                $pdo->exec("ALTER TABLE users ADD COLUMN totp_backup_codes TEXT DEFAULT NULL");
            } catch (Exception $e) {
                // Columns might already exist
            }
            
            // Generate backup codes
            $backup_codes = [];
            for ($i = 0; $i < 10; $i++) {
                $backup_codes[] = sprintf('%08d', random_int(10000000, 99999999));
            }
            
            $stmt = $pdo->prepare("UPDATE users SET totp_secret = ?, totp_enabled = 1, totp_backup_codes = ? WHERE id = ?");
            $stmt->execute([$secret, json_encode($backup_codes), $user_id]);
            
            return $backup_codes;
        } catch (Exception $e) {
            error_log("2FA enable error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Check if user has 2FA enabled
     */
    public static function isEnabledForUser($user_id) {
        try {
            require_once 'config_paths.php';
            $db_path = ConfigPaths::getDatabase('users');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("SELECT totp_enabled FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result && $result['totp_enabled'] == 1;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Get user's 2FA secret
     */
    public static function getUserSecret($user_id) {
        try {
            require_once 'config_paths.php';
            $pdo = self::getDatabaseConnection();
            
            $stmt = $pdo->prepare("SELECT totp_secret FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            return $result ? $result['totp_secret'] : null;
        } catch (Exception $e) {
            error_log("TwoFactorAuth::getUserSecret error: " . $e->getMessage());
            return null;
        }
    }
    
    /**
     * Verify backup code
     */
    public static function verifyBackupCode($user_id, $code) {
        try {
            $pdo = self::getDatabaseConnection();
            
            $stmt = $pdo->prepare("SELECT totp_backup_codes FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result) return false;
            
            $backup_codes = json_decode($result['totp_backup_codes'], true);
            if (!$backup_codes) return false;
            
            $key = array_search($code, $backup_codes);
            if ($key !== false) {
                // Remove used backup code
                unset($backup_codes[$key]);
                
                $stmt = $pdo->prepare("UPDATE users SET totp_backup_codes = ? WHERE id = ?");
                $stmt->execute([json_encode(array_values($backup_codes)), $user_id]);
                
                return true;
            }
            
            return false;
        } catch (Exception $e) {
            return false;
        }
    }
    
    /**
     * Get backup codes count for user
     */
    public static function getBackupCodesCount($user_id) {
        try {
            require_once 'config_paths.php';
            $db_path = ConfigPaths::getDatabase('users');
            $pdo = new PDO("sqlite:$db_path");
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            
            $stmt = $pdo->prepare("SELECT totp_backup_codes FROM users WHERE id = ?");
            $stmt->execute([$user_id]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if (!$result) return 0;
            
            $backup_codes = json_decode($result['totp_backup_codes'], true);
            return $backup_codes ? count($backup_codes) : 0;
        } catch (Exception $e) {
            return 0;
        }
    }
    
    /**
     * Base32 decoder (simplified for TOTP)
     */
    private static function base32Decode($input) {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
        $output = '';
        $v = 0;
        $vbits = 0;
        
        for ($i = 0; $i < strlen($input); $i++) {
            $value = strpos($alphabet, $input[$i]);
            if ($value === false) continue;
            
            $v = ($v << 5) | $value;
            $vbits += 5;
            
            if ($vbits >= 8) {
                $output .= chr(($v >> ($vbits - 8)) & 255);
                $vbits -= 8;
            }
        }
        
        return $output;
    }
}
?>