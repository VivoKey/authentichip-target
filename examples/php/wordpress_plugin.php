<?php
/**
 * Plugin Name: AuthentiChip Integration
 * Description: Validates AuthentiChip JWT tokens and provides action hooks for integration
 * Version: 1.0.0
 * Author: Your Name
 * License: CC0 1.0 Universal
 *
 * Installation:
 * 1. Create directory: wp-content/plugins/authentichip/
 * 2. Copy this file to: wp-content/plugins/authentichip/wordpress_plugin.php
 * 3. Install dependencies: Run `composer require firebase/php-jwt` in the plugin directory
 * 4. Activate the plugin in WordPress admin
 *
 * Usage in your theme or another plugin:
 *
 * // Handle verified scans
 * add_action('authentichip_verified', function($chipId) {
 *     error_log("Verified chip: " . $chipId);
 *     // Look up product, grant access, etc.
 * });
 *
 * // Handle unverified scans
 * add_action('authentichip_unverified', function($uid, $status) {
 *     error_log("Unverified scan - UID: $uid, Status: $status");
 *     // Log attempt, show limited info, etc.
 * }, 10, 2);
 */

if (!defined('ABSPATH')) {
    exit; // Exit if accessed directly
}

// Load Composer dependencies
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
} else {
    add_action('admin_notices', function() {
        echo '<div class="error"><p>AuthentiChip: Please run <code>composer install</code> in the plugin directory.</p></div>';
    });
    return;
}

use Firebase\JWT\JWT;
use Firebase\JWT\JWK;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\SignatureInvalidException;

class AuthentiChip_Integration {

    private $jwks_cache_key = 'authentichip_jwks';
    private $jwks_cache_expiry = 21600; // 6 hours

    public function __construct() {
        // Hook into WordPress init
        add_action('init', [$this, 'check_authentication']);

        // Add shortcode for displaying chip info
        add_shortcode('authentichip_info', [$this, 'shortcode_chip_info']);

        // Add REST API endpoint
        add_action('rest_api_init', [$this, 'register_rest_routes']);
    }

    /**
     * Check for AuthentiChip parameters on every page load
     */
    public function check_authentication() {
        $jwt = isset($_GET['vkjwt']) ? sanitize_text_field($_GET['vkjwt']) : null;
        $status = isset($_GET['vkstatus']) ? sanitize_text_field($_GET['vkstatus']) : null;
        $uid = isset($_GET['vkuid']) ? sanitize_text_field($_GET['vkuid']) : null;

        if ($jwt) {
            try {
                $chipId = $this->validate_jwt($jwt);

                // Store in session for later use
                if (!session_id()) {
                    session_start();
                }
                $_SESSION['authentichip_id'] = $chipId;
                $_SESSION['authentichip_verified'] = true;
                $_SESSION['authentichip_timestamp'] = time();

                // Fire action hook for other plugins/themes
                do_action('authentichip_verified', $chipId);

                // Optional: Store in user meta if logged in
                if (is_user_logged_in()) {
                    update_user_meta(get_current_user_id(), 'last_chip_scan', [
                        'chip_id' => $chipId,
                        'timestamp' => time(),
                        'verified' => true,
                    ]);
                }

            } catch (Exception $e) {
                // Log validation failure
                error_log('AuthentiChip validation failed: ' . $e->getMessage());

                do_action('authentichip_validation_failed', $e->getMessage());
            }

        } elseif ($status && $uid) {
            // Unverified scan
            if (!session_id()) {
                session_start();
            }
            $_SESSION['authentichip_uid'] = $uid;
            $_SESSION['authentichip_status'] = $status;
            $_SESSION['authentichip_verified'] = false;
            $_SESSION['authentichip_timestamp'] = time();

            do_action('authentichip_unverified', $uid, $status);

            if (is_user_logged_in()) {
                update_user_meta(get_current_user_id(), 'last_chip_scan', [
                    'uid' => $uid,
                    'status' => $status,
                    'timestamp' => time(),
                    'verified' => false,
                ]);
            }
        }
    }

    /**
     * Validate JWT and extract chip ID
     */
    private function validate_jwt($jwt) {
        // Get cached JWKS or fetch fresh
        $jwks = get_transient($this->jwks_cache_key);

        if (false === $jwks) {
            $response = wp_remote_get('https://auth.vivokey.com/.well-known/jwks.json', [
                'timeout' => 10,
            ]);

            if (is_wp_error($response)) {
                throw new Exception('Unable to fetch JWKS: ' . $response->get_error_message());
            }

            $body = wp_remote_retrieve_body($response);
            $jwks = json_decode($body, true);

            if (!$jwks || !isset($jwks['keys'])) {
                throw new Exception('Invalid JWKS response');
            }

            // Cache the JWKS
            set_transient($this->jwks_cache_key, $jwks, $this->jwks_cache_expiry);
        }

        // Parse and validate
        $keys = JWK::parseKeySet($jwks);
        $decoded = JWT::decode($jwt, $keys);

        // Verify issuer
        if (!isset($decoded->iss) || $decoded->iss !== 'auth.vivokey.com') {
            throw new Exception('Invalid issuer');
        }

        // Extract chip ID
        if (!isset($decoded->sub) || empty($decoded->sub)) {
            throw new Exception('Missing chip ID');
        }

        return $decoded->sub;
    }

    /**
     * Shortcode to display chip information
     * Usage: [authentichip_info]
     */
    public function shortcode_chip_info($atts) {
        if (!session_id()) {
            session_start();
        }

        $verified = $_SESSION['authentichip_verified'] ?? false;

        if ($verified) {
            $chipId = $_SESSION['authentichip_id'] ?? 'Unknown';
            $output = '<div class="authentichip-verified">';
            $output .= '<p><strong>Verified Chip</strong></p>';
            $output .= '<p>Chip ID: ' . esc_html($chipId) . '</p>';
            $output .= '</div>';
        } else {
            $status = $_SESSION['authentichip_status'] ?? null;
            $uid = $_SESSION['authentichip_uid'] ?? null;

            if ($status && $uid) {
                $output = '<div class="authentichip-unverified">';
                $output .= '<p><strong>Unverified Scan</strong></p>';
                $output .= '<p>Status: ' . esc_html($status) . '</p>';
                $output .= '<p>UID: ' . esc_html($uid) . '</p>';
                $output .= '</div>';
            } else {
                $output = '<p>No chip scan detected.</p>';
            }
        }

        return $output;
    }

    /**
     * Register REST API endpoints
     */
    public function register_rest_routes() {
        register_rest_route('authentichip/v1', '/verify', [
            'methods' => 'GET',
            'callback' => [$this, 'rest_verify'],
            'permission_callback' => '__return_true',
        ]);
    }

    /**
     * REST API endpoint for external verification
     * GET /wp-json/authentichip/v1/verify?vkjwt=...
     */
    public function rest_verify($request) {
        $jwt = $request->get_param('vkjwt');

        if (!$jwt) {
            return new WP_Error('no_jwt', 'No JWT provided', ['status' => 400]);
        }

        try {
            $chipId = $this->validate_jwt($jwt);

            return [
                'verified' => true,
                'chip_id' => $chipId,
            ];

        } catch (Exception $e) {
            return new WP_Error('validation_failed', $e->getMessage(), ['status' => 401]);
        }
    }
}

// Initialize the plugin
new AuthentiChip_Integration();
