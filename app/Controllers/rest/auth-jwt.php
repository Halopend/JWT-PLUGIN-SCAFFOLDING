<?php
/* Modifed from https://github.com/usefulteam/jwt-auth distributed under the GPL 3.0 License */

// Uses the following parameters for configuration:
// define('AUTH_JWT_SECRET_KEY', 'your-top-secret-key'); // required
// define('AUTH_JWT_PARAM_TRANSPORT_METHOD', 'json'); 	 // optional- see get_token() for possible values

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AUTH_JWT_Rest extends WP_REST_Controller
{	
	const ENCRYPTION_METHOD = 'HS256';
	/**
	 * Register the routes for the objects of the controller.
	 */
	public function register_routes()
	{
		$version = '1';
		$namespace = 'jwt/v' . $version;
		register_rest_route(
			$namespace,
			'token',
			array(
				'methods'             => array('POST'),
				'callback'            => array($this, 'get_token'),
				'permission_callback' => '__return_true',
			)
		);

		register_rest_route(
			$namespace,
			'token/validate',
			array(
				'methods'             => 'POST',
				'callback'            => array($this, 'validate_token'),
				'permission_callback' => '__return_true',
			)
		);
	}


	/**
	 * Get token by sending POST request to jwt/v1/token.
	 *
	 * @param WP_REST_Request $request The request.
	 * @return WP_REST_Response The response.
	 */
	public function get_token( WP_REST_Request $request ) {
		$secret_key = defined( 'AUTH_JWT_SECRET_KEY' ) ? AUTH_JWT_SECRET_KEY : false;
		$transport_method = defined( 'AUTH_JWT_PARAM_TRANSPORT_METHOD' ) ? AUTH_JWT_PARAM_TRANSPORT_METHOD : 'rest_param';

		switch ($transport_method){
			case 'rest_param': // works for both form encoded and url_queries
				$username    = $request->get_param( 'username' );
				$password    = $request->get_param( 'password' );
				$custom_auth = $request->get_param( 'custom_auth' );
				break;
			case 'json':
				$params = $request->get_json_params();
				$username = $params['username'] ?? null;
				$password = $params['password'] ?? null;
				$custom_auth = null; //@todo --  implement custom auth in json support
				break;
		}
		
		// First thing, check the secret key if not exist return a error.
		if ( ! $secret_key ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'auth_jwt_bad_config',
					'message'    => __( 'Please define var AUTH_JWT_SECRET_KEY in config.', 'auth-jwt' ),
					'data'       => array(),
				),
				403
			);
		}

		$user = $this->authenticate_user( $username, $password, $custom_auth );

		// If the authentication is failed return error response.
		if ( is_wp_error( $user ) ) {
			// $error_code = $user->get_error_code();
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'Username and/or password incorrect',
					'data'       => array('Expected Transport Method'=> $transport_method),
				),
				403
			);
		}

		// Valid credentials, the user exists, let's generate the token.
		return $this->generate_token( $user, false );
	}

	/**
	 * Generate token
	 *
	 * @param WP_User $user The WP_User object.
	 * @param bool    $return_raw Whether or not to return as raw token string.
	 *
	 * @return WP_REST_Response|string Return as raw token string or as a formatted WP_REST_Response.
	 */
	public function generate_token( $user, $return_raw = true ) {
		$secret_key = defined( 'AUTH_JWT_SECRET_KEY' ) ? AUTH_JWT_SECRET_KEY : false;
		$issued_at  = time();
		$not_before = $issued_at;
		$not_before = apply_filters( 'auth_jwt_not_before', $not_before, $issued_at );
		$expire     = $issued_at + ( DAY_IN_SECONDS * 7 );
		$expire     = apply_filters( 'auth_jwt_expire', $expire, $issued_at );

		$payload = array(
			'iss'  => site_url(),
			'iat'  => $issued_at,
			'nbf'  => $not_before,
			'exp'  => $expire,
			'data' => array(
				'user' => array(
					'id' => $user->ID,
				),
			),
		);

		// Let the user modify the token data before the sign.
		$token = JWT::encode( apply_filters( 'auth_jwt_payload', $payload, $user ), $secret_key, self::ENCRYPTION_METHOD );

		// If return as raw token string.
		if ( $return_raw ) {
			return $token;
		}

		// The token is signed, now create object with basic info of the user.
		$response = array(
			'success'    => true,
			'statusCode' => 200,
			'code'       => 'auth_jwt_valid_credential',
			'message'    => __( 'Credential is valid', 'jwt-auth' ),
			'data'       => array(
				'token'       => $token,
				'id'          => $user->ID,
				'email'       => $user->user_email,
				'nicename'    => $user->user_nicename,
				'firstName'   => $user->first_name,
				'lastName'    => $user->last_name,
				'displayName' => $user->display_name,
			),
		);

		// Let the user modify the data before send it back.
		return apply_filters( 'auth_jwt_valid_credential_response', $response, $user );
	}

	/**
	 * Authenticate user either via wp_authenticate or custom auth (e.g: OTP).
	 *
	 * @param string $username The username.
	 * @param string $password The password.
	 * @param mixed  $custom_auth The custom auth data (if any).
	 *
	 * @return WP_User|WP_Error $user Returns WP_User object if success, or WP_Error if failed.
	 */
	public function authenticate_user( $username, $password, $custom_auth = '' ) {
		// If using custom authentication.
		if ( $custom_auth ) {
			$custom_auth_error = new WP_Error( 'auth_jwt_custom_auth_failed', __( 'Custom authentication failed.', 'jwt-auth' ) );

			/**
			 * Do your own custom authentication and return the result through this filter.
			 * It should return either WP_User or WP_Error.
			 */
			$user = apply_filters( 'auth_jwt_do_custom_auth', $custom_auth_error, $username, $password, $custom_auth );
		} else {
			$user = wp_authenticate( $username, $password );
		}
		return $user;
	}



	/**
	 * Main validation function, this function try to get the Autentication
	 * headers and decoded.
	 *
	 * @param bool $return_response Either to return full WP_REST_Response or to return the payload only.
	 *
	 * @return WP_REST_Response | Array Returns WP_REST_Response or token's $payload.
	 */
	public function validate_token( $return_response = true ) {
		/**
		 * Looking for the HTTP_AUTHORIZATION header, if not present just
		 * return the user.
		 */
		$headerkey = apply_filters( 'jwt_auth_authorization_header', 'HTTP_AUTHORIZATION' );
		$auth      = isset( $_SERVER[ $headerkey ] ) ? sanitize_text_field( wp_unslash( $_SERVER[ $headerkey ] ) ) : false;

		// Double check for different auth header string (server dependent).
		if ( ! $auth ) {
			$auth = isset( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ) ) : false;
		}

		if ( ! $auth ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'jwt_auth_no_auth_header',
					'message'    => $this->messages['jwt_auth_no_auth_header'],
					'data'       => array(),
				)
			);
		}

		/**
		 * The HTTP_AUTHORIZATION is present, verify the format.
		 * If the format is wrong return the user.
		 */
		list($token) = sscanf( $auth, 'Bearer %s' );

		if ( ! $token ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'jwt_auth_bad_auth_header',
					'message'    => $this->messages['jwt_auth_bad_auth_header'],
					'data'       => array(),
				)
			);
		}

		// Get the Secret Key.
		$secret_key = defined( 'AUTH_JWT_SECRET_KEY' ) ? AUTH_JWT_SECRET_KEY : false;

		if ( ! $secret_key ) {
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'jwt_auth_bad_config',
					'message'    => __( 'JWT is not configured properly.', 'jwt-auth' ),
					'data'       => array(),
				),
				403
			);
		}

		// Try to decode the token.
		try {
			$payload = JWT::decode( $token, new Key( $secret_key , self::ENCRYPTION_METHOD ));

			// The Token is decoded now validate the iss.
			if ( $payload->iss !== site_url() ) {
				// The iss do not match, return error.
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'jwt_auth_bad_iss',
						'message'    => __( 'The iss do not match with this server.', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Check the user id existence in the token.
			if ( ! isset( $payload->data->user->id ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'jwt_auth_bad_request',
						'message'    => __( 'User ID not found in the token.', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// So far so good, check if the given user id exists in db.
			$user = get_user_by( 'id', $payload->data->user->id );

			if ( ! $user ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'jwt_auth_user_not_found',
						'message'    => __( "User doesn't exist", 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Check extra condition if exists.
			$failed_msg = apply_filters( 'jwt_auth_extra_token_check', '', $user, $token, $payload );

			if ( ! empty( $failed_msg ) ) {
				// No user id in the token, abort!!
				return new WP_REST_Response(
					array(
						'success'    => false,
						'statusCode' => 403,
						'code'       => 'jwt_auth_obsolete_token',
						'message'    => __( 'Token is obsolete', 'jwt-auth' ),
						'data'       => array(),
					),
					403
				);
			}

			// Everything looks good, return the payload if $return_response is set to false.
			if ( ! $return_response ) {
				return $payload;
			}

			$response = array(
				'success'    => true,
				'statusCode' => 200,
				'code'       => 'jwt_auth_valid_token',
				'message'    => __( 'Token is valid', 'jwt-auth' ),
				'data'       => array(),
			);

			$response = apply_filters( 'jwt_auth_valid_token_response', $response, $user, $token, $payload );

			// Otherwise, return success response.
			return new WP_REST_Response( $response );
		} catch ( Exception $e ) {
			// Something is wrong when trying to decode the token, return error response.
			return new WP_REST_Response(
				array(
					'success'    => false,
					'statusCode' => 403,
					'code'       => 'jwt_auth_invalid_token',
					'message'    => $e->getMessage(),
					'data'       => array(),
				),
				403
			);
		}
	}
}

/**
 * Function to register our new routes from the controller.
 */
function register_jwt_controller()
{
	$controller = new AUTH_JWT_Rest();
	$controller->register_routes();
}

add_action('rest_api_init', 'register_jwt_controller');
