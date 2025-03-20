<?php

class plugin_ldap {
    public $debug = true; // Keep debugging enabled
    public $domain_name;
    public $username;
    public $password;
    public $user_uuid;
    public $contact_uuid;
    
    private $log_file = '/var/log/freeswitch/ldap_debug.log';

    function ldap() {
        // Get username and password from request
        $this->username = isset($_REQUEST["username"]) ? $_REQUEST["username"] : "*****";
        $this->password = isset($_REQUEST["password"]) ? $_REQUEST["password"] : "*****";

        // Log initial details
        error_log("ldap: Received username: " . $this->username . "\n", 3, $this->log_file);
        error_log("ldap: Session settings and domain details:\n", 3, $this->log_file);
        error_log("ldap: Domain UUID: " . ($_SESSION["domain_uuid"] ?? 'None') . "\n", 3, $this->log_file);
        error_log("ldap: Domain Name: " . ($_SESSION["domain_name"] ?? 'None') . "\n", 3, $this->log_file);
        error_log("ldap: LDAP server host: " . ($_SESSION["ldap"]["server_host"]["text"] ?? 'None') . "\n", 3, $this->log_file);
        error_log("ldap: LDAP server port: " . ($_SESSION["ldap"]["server_port"]["numeric"] ?? 'None') . "\n", 3, $this->log_file);
        error_log("ldap: LDAP user_dn: " . ($_SESSION["ldap"]["user_dn"]["text"] ?? 'None') . "\n", 3, $this->log_file);

        if ($this->debug) {
            error_log("ldap: Debugging enabled. Username: " . $this->username . " Password: " . $this->password . "\n", 3, $this->log_file);
        }

        // Connect to LDAP server
        $host = $_SESSION["ldap"]["server_host"]["text"];
        $port = $_SESSION["ldap"]["server_port"]["numeric"];
        error_log("ldap: Connecting to LDAP server at $host:$port\n", 3, $this->log_file);
        $connect = ldap_connect($host, $port);
        if (!$connect) {
            error_log("ldap: Failed to connect to LDAP server at $host:$port\n", 3, $this->log_file);
            die("Could not connect to the LDAP server.");
        }

        // Set LDAP options
        ldap_set_option($connect, LDAP_OPT_PROTOCOL_VERSION, 3);
        ldap_set_option($connect, LDAP_OPT_REFERRALS, 0);
        error_log("ldap: Set LDAP protocol version to 3\n", 3, $this->log_file);

        // Default authorization status
        $user_authorized = false;

        // Use UPN format for binding
        $bind_dn = "{$this->username}@basehn.local"; // Proven to work with ldapsearch
        error_log("ldap: Trying to bind with UPN: $bind_dn\n", 3, $this->log_file);

        // Attempt to bind
        $bind = @ldap_bind($connect, $bind_dn, $this->password);
        if ($bind) {
            $user_authorized = true;
            error_log("ldap: LDAP bind successful with UPN\n", 3, $this->log_file);
        } else {
            $error = ldap_error($connect);
            $errno = ldap_errno($connect);
            error_log("ldap: LDAP bind failed for UPN: $bind_dn - Error: $error ($errno)\n", 3, $this->log_file);
        }

        // Handle user authorization (your existing logic)
        if ($user_authorized) {
            error_log("ldap: User authorized\n", 3, $this->log_file);
            $sql = "select * from v_users ";
            $sql .= "where username = :username ";
            if ($settings['users']['unique'] != "global") {
                $sql .= "and domain_uuid = :domain_uuid ";
                $parameters['domain_uuid'] = $this->domain_uuid;
            }
            $sql .= "and (user_type = 'default' or user_type is null) ";
            $parameters['username'] = $this->username;
            $database = new database;
            $row = $database->select($sql, $parameters, 'row');
            if (is_array($row) && @sizeof($row) != 0) {
                error_log("ldap: Found existing user with username: " . $this->username . "\n", 3, $this->log_file);
                // Add your domain mismatch logic here if needed
                $this->user_uuid = $row["user_uuid"];
                $this->contact_uuid = $row["contact_uuid"];
            } else {
					error_log("ldap: User does not exist, creating new user.\n", 3, $this->log_file);
					//salt used with the password to create a one way hash
						$salt = generate_password('32', '4');
						$password = generate_password('32', '4');

					//prepare the uuids
						$this->user_uuid = uuid();
						$this->contact_uuid = uuid();

					//build user insert array
						$array['users'][0]['user_uuid'] = $this->user_uuid;
						$array['users'][0]['domain_uuid'] = $this->domain_uuid;
						$array['users'][0]['contact_uuid'] = $this->contact_uuid;
						$array['users'][0]['username'] = strtolower($this->username);
						$array['users'][0]['password'] = md5($salt.$password);
						$array['users'][0]['salt'] = $salt;
						$array['users'][0]['add_date'] = date('Y-m-d H:i:s');
						$array['users'][0]['add_user'] = strtolower($this->username);
						$array['users'][0]['user_enabled'] = 'true';
						$array['users'][0]['user_type'] = 'default';

					//build user group insert array
						$array['user_groups'][0]['user_group_uuid'] = uuid();
						$array['user_groups'][0]['domain_uuid'] = $this->domain_uuid;
						$array['user_groups'][0]['group_name'] = 'user';
						$array['user_groups'][0]['user_uuid'] = $this->user_uuid;
						$array['user_groups'][0]['group_uuid'] = '54f75a42-b1cb-40f2-b8b0-784cdaeb7427';

					//grant temporary permissions
						$p = permissions::new();
						$p->add('user_add', 'temp');
						$p->add('user_group_add', 'temp');

					//execute insert
						$database = new database;
						$database->app_name = 'authentication';
						$database->app_uuid = 'a8a12918-69a4-4ece-a1ae-3932be0e41f1';
						$database->save($array);
						unset($array);

					//revoke temporary permissions
						$p->delete('user_add', 'temp');
						$p->delete('user_group_add', 'temp');
				}           
            unset($sql, $parameters, $row);
        }

        // Prepare result
        $result["ldap"]["plugin"] = "ldap";
        $result["ldap"]["domain_name"] = $this->domain_name;
        $result["ldap"]["username"] = $this->username;
        if ($this->debug) {
            $result["ldap"]["password"] = $this->password;
        }
        $result["ldap"]["user_uuid"] = $this->user_uuid;
        $result["ldap"]["domain_uuid"] = $this->domain_uuid;
        $result["ldap"]["authorized"] = $user_authorized;

        error_log("ldap: Final authorization result: " . ($user_authorized ? "authorized" : "not authorized") . "\n", 3, $this->log_file);

        ldap_close($connect);
        return $result;
    }
}

?>
