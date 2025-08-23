<?php
/**
 * Secure File Access Handler
 * Prevents directory traversal and unauthorized file access
 */

require_once 'input_sanitizer.php';
require_once 'security_middleware.php';
require_once 'secure_error_handler.php';

class SecureFileHandler {
    
    private static $allowedPaths = [
        '/home/cr0/cr0bot/logs/',
        '/var/www/html/data/',
        '/tmp/',
        '/home/cr0/cr0bot/data/'
    ];
    
    private static $allowedExtensions = [
        'log', 'txt', 'json', 'db', 'sql', 'csv'
    ];
    
    /**
     * Securely read file with comprehensive validation
     */
    public static function readFile($filepath, $maxSize = 1048576) { // 1MB default limit
        // Initial path validation
        $validatedPath = InputSanitizer::validateFilePath($filepath);
        if (!$validatedPath) {
            return SecureErrorHandler::handleFileError(
                "Invalid file path: $filepath", 
                $filepath
            );
        }
        
        // Check if file exists
        if (!file_exists($validatedPath)) {
            return SecureErrorHandler::handleFileError(
                "File not found: $validatedPath", 
                $validatedPath
            );
        }
        
        // Check file size
        $fileSize = filesize($validatedPath);
        if ($fileSize > $maxSize) {
            SecurityMiddleware::logSecurityEvent('LARGE_FILE_ACCESS_ATTEMPT', [
                'file' => $validatedPath,
                'size' => $fileSize,
                'max_allowed' => $maxSize,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'MEDIUM');
            
            return ['error' => 'File too large to read'];
        }
        
        // Validate file extension
        $extension = strtolower(pathinfo($validatedPath, PATHINFO_EXTENSION));
        if (!in_array($extension, self::$allowedExtensions)) {
            SecurityMiddleware::logSecurityEvent('UNAUTHORIZED_FILE_TYPE_ACCESS', [
                'file' => $validatedPath,
                'extension' => $extension,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'HIGH');
            
            return ['error' => 'File type not allowed'];
        }
        
        // Additional security check for path traversal
        if (!self::isPathSafe($validatedPath)) {
            SecurityMiddleware::logSecurityEvent('PATH_TRAVERSAL_BLOCKED', [
                'original_path' => $filepath,
                'resolved_path' => $validatedPath,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'HIGH');
            
            return ['error' => 'Access denied'];
        }
        
        try {
            $content = file_get_contents($validatedPath);
            
            if ($content === false) {
                return SecureErrorHandler::handleFileError(
                    "Failed to read file: $validatedPath", 
                    $validatedPath
                );
            }
            
            // Log successful access for audit
            SecurityMiddleware::logSecurityEvent('FILE_ACCESS', [
                'file' => $validatedPath,
                'size' => strlen($content),
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'INFO');
            
            return [
                'success' => true,
                'content' => $content,
                'size' => strlen($content),
                'modified' => filemtime($validatedPath)
            ];
            
        } catch (Exception $e) {
            return SecureErrorHandler::handleFileError(
                "File read error: " . $e->getMessage(), 
                $validatedPath
            );
        }
    }
    
    /**
     * Get file information securely
     */
    public static function getFileInfo($filepath) {
        $validatedPath = InputSanitizer::validateFilePath($filepath);
        if (!$validatedPath) {
            return ['error' => 'Invalid file path'];
        }
        
        if (!file_exists($validatedPath)) {
            return ['error' => 'File not found'];
        }
        
        if (!self::isPathSafe($validatedPath)) {
            return ['error' => 'Access denied'];
        }
        
        try {
            $stat = stat($validatedPath);
            return [
                'success' => true,
                'exists' => true,
                'size' => $stat['size'],
                'size_human' => self::formatBytes($stat['size']),
                'last_modified' => $stat['mtime'],
                'last_modified_human' => date('Y-m-d H:i:s', $stat['mtime']),
                'is_readable' => is_readable($validatedPath),
                'extension' => strtolower(pathinfo($validatedPath, PATHINFO_EXTENSION))
            ];
        } catch (Exception $e) {
            return SecureErrorHandler::handleFileError(
                "File stat error: " . $e->getMessage(), 
                $validatedPath
            );
        }
    }
    
    /**
     * List files in directory securely
     */
    public static function listDirectory($directoryPath, $pattern = '*') {
        $validatedPath = InputSanitizer::validateFilePath($directoryPath);
        if (!$validatedPath) {
            return ['error' => 'Invalid directory path'];
        }
        
        if (!is_dir($validatedPath)) {
            return ['error' => 'Directory not found'];
        }
        
        if (!self::isPathSafe($validatedPath)) {
            return ['error' => 'Access denied'];
        }
        
        try {
            // Sanitize pattern to prevent injection
            $pattern = preg_replace('/[^a-zA-Z0-9.*_-]/', '', $pattern);
            
            $files = glob($validatedPath . '/' . $pattern);
            $result = [];
            
            foreach ($files as $file) {
                if (self::isPathSafe($file)) {
                    $info = self::getFileInfo($file);
                    if (isset($info['success'])) {
                        $result[] = [
                            'name' => basename($file),
                            'path' => $file,
                            'size' => $info['size'],
                            'size_human' => $info['size_human'],
                            'modified' => $info['last_modified'],
                            'modified_human' => $info['last_modified_human'],
                            'is_file' => is_file($file),
                            'is_dir' => is_dir($file)
                        ];
                    }
                }
            }
            
            return [
                'success' => true,
                'files' => $result,
                'count' => count($result)
            ];
            
        } catch (Exception $e) {
            return SecureErrorHandler::handleFileError(
                "Directory listing error: " . $e->getMessage(), 
                $validatedPath
            );
        }
    }
    
    /**
     * Read log file with tail functionality
     */
    public static function readLogFile($filepath, $lines = 100) {
        $fileInfo = self::readFile($filepath);
        if (isset($fileInfo['error'])) {
            return $fileInfo;
        }
        
        $content = $fileInfo['content'];
        
        // If file is small, return as-is
        if (strlen($content) < 10000) {
            return [
                'success' => true,
                'content' => $content,
                'total_lines' => substr_count($content, "\n"),
                'returned_lines' => substr_count($content, "\n")
            ];
        }
        
        // For large files, return last N lines
        $contentLines = explode("\n", $content);
        $totalLines = count($contentLines);
        
        if ($totalLines > $lines) {
            $contentLines = array_slice($contentLines, -$lines);
        }
        
        return [
            'success' => true,
            'content' => implode("\n", $contentLines),
            'total_lines' => $totalLines,
            'returned_lines' => count($contentLines),
            'truncated' => $totalLines > $lines
        ];
    }
    
    /**
     * Check if path is within allowed directories
     */
    private static function isPathSafe($path) {
        $realPath = realpath($path);
        if (!$realPath) {
            return false;
        }
        
        foreach (self::$allowedPaths as $allowedPath) {
            $allowedReal = realpath($allowedPath);
            if ($allowedReal && strpos($realPath, $allowedReal) === 0) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Format bytes to human readable format
     */
    private static function formatBytes($size) {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        for ($i = 0; $size > 1024 && $i < count($units) - 1; $i++) {
            $size /= 1024;
        }
        return round($size, 2) . ' ' . $units[$i];
    }
    
    /**
     * Write to file securely (for logging purposes)
     */
    public static function secureWrite($filepath, $content, $append = true) {
        $validatedPath = InputSanitizer::validateFilePath($filepath);
        if (!$validatedPath) {
            return ['error' => 'Invalid file path'];
        }
        
        if (!self::isPathSafe($validatedPath)) {
            return ['error' => 'Access denied'];
        }
        
        // Check if directory exists, create if necessary
        $directory = dirname($validatedPath);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true)) {
                return ['error' => 'Failed to create directory'];
            }
        }
        
        try {
            $flags = $append ? FILE_APPEND | LOCK_EX : LOCK_EX;
            $result = file_put_contents($validatedPath, $content, $flags);
            
            if ($result === false) {
                return ['error' => 'Failed to write file'];
            }
            
            return [
                'success' => true,
                'bytes_written' => $result,
                'file' => $validatedPath
            ];
            
        } catch (Exception $e) {
            return SecureErrorHandler::handleFileError(
                "File write error: " . $e->getMessage(), 
                $validatedPath
            );
        }
    }
    
    /**
     * Delete file securely (with audit trail)
     */
    public static function secureDelete($filepath) {
        $validatedPath = InputSanitizer::validateFilePath($filepath);
        if (!$validatedPath) {
            return ['error' => 'Invalid file path'];
        }
        
        if (!file_exists($validatedPath)) {
            return ['error' => 'File not found'];
        }
        
        if (!self::isPathSafe($validatedPath)) {
            SecurityMiddleware::logSecurityEvent('UNAUTHORIZED_DELETE_ATTEMPT', [
                'file' => $filepath,
                'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
            ], 'HIGH');
            return ['error' => 'Access denied'];
        }
        
        // Log deletion attempt
        SecurityMiddleware::logSecurityEvent('FILE_DELETION', [
            'file' => $validatedPath,
            'size' => filesize($validatedPath),
            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
        ], 'MEDIUM');
        
        try {
            if (unlink($validatedPath)) {
                return ['success' => true, 'message' => 'File deleted successfully'];
            } else {
                return ['error' => 'Failed to delete file'];
            }
        } catch (Exception $e) {
            return SecureErrorHandler::handleFileError(
                "File deletion error: " . $e->getMessage(), 
                $validatedPath
            );
        }
    }
    
    /**
     * Add allowed path (for extending functionality)
     */
    public static function addAllowedPath($path) {
        $realPath = realpath($path);
        if ($realPath && is_dir($realPath)) {
            self::$allowedPaths[] = $realPath . '/';
            return true;
        }
        return false;
    }
    
    /**
     * Add allowed file extension
     */
    public static function addAllowedExtension($extension) {
        $extension = strtolower(trim($extension, '.'));
        if (!in_array($extension, self::$allowedExtensions)) {
            self::$allowedExtensions[] = $extension;
            return true;
        }
        return false;
    }
}
?>