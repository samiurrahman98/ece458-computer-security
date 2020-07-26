<?php

/******************************************************************************
 * This file contains the server side PHP code that students need to modify 
 * to implement the password safe application.  Another PHP file, server.php,
 * must not be modified and handles initialization of some variables,
 * resource arbitration, and outputs the reponse.  The last PHP file is api.php
 * which also must not be modified by students and which provides an API
 * for resource functions to communicate with clients.
 * 
 * Student code in this file must only interact with the outside world via
 * the parameters to the functions.  These parameters are the same for each 
 * function.  The Request and Reponse classes can be found in api.php.
 * For more information on PDO database connections, see the documentation at
 * https://www.php.net/manual/en/book.pdo.php or other websites.
 *
 * The parameters to each function are:
 *   -- $request A Request object, passed by reference (see api.php)
 *   -- $response A Response object, passed by reference (see api.php)
 *   -- $db A PDO database connection, passed by reference
 *
 * The functions must also return the same values.  They are:
 *   -- true on success, false on failure
 *
 * Students should understand how to use the Request and Response objects, so
 * please spend some time looking at the code in api.php.  Apart from those
 * classes, the only other API function that students should use is the
 * log_to_console function, which MUST be used for server-side logging.
 *
 * The functions that need to be implemented all handle a specific type of
 * request from the client.  These map to the resources the client JavaScript
 * will call when the user performs certain actions.
 * The functions are:
 *    - preflight -- This is a special function in that it is called both 
 *                   as a separate "preflight" resource and it is also called
 *                   before every other resource to perform any preflight 
 *                   checks and insert any preflight response.  It is 
 *                   especially important that preflight returns true if the
 *                   request succeeds and false if something is wrong.
 *                   See server.php to see how preflight is called.
 *    - signup -- This resource should create a new account for the user
 *                if there are no problems with the request.
 *    - identify -- This resource identifies a user and returns any 
 *                  information that the client would need to log in.  You 
 *                  should be especially careful not to leak any information 
 *                  through this resource.
 *    - login -- This resource checks user credentials and, if they are valid,
 *               creates a new session.
 *    - sites -- This resource should return a list of sites that are saved
 *               for a logged in user.  This result is used to populate the 
 *               dropdown select elements in the user interface.
 *    - save -- This resource saves a new (or replaces an existing) entry in 
 *              the password safe for a logged in user.
 *    - load -- This resource loads an existing entry from the password safe
 *              for a logged in user.
 *    - logout -- This resource should destroy the existing user session.
 *
 * It is VERY important that resources set appropriate HTTP response codes!
 * If a resource returns a 5xx code (which is the default and also what PHP 
 * will set if there is an error executing the script) then we will assume  
 * there is a bug in the program during grading.  Similarly, if a resource
 * returns a 2xx code when it should fail, or a 4xx code when it should 
 * succeed, then I will assume it has done the wrong thing.
 *
 * You should not worry about the database getting full of old entries, so
 * don't feel the need to delete expired or invalid entries at any point.
 *
 * The database connection is to the sqlite3 database "passwordsafe.db".
 * The commands to create this database (and therefore its schema) can
 * be found in "initdb.sql".  You should familiarize yourself with this
 * schema.  Not every table or field must be used, but there are many 
 * helpful hints contained therein.
 * The database can be accessed to run queries on it with the command:
 *    sqlite3 passwordsafe.db
 * It is also easy to run SQL scripts on it by sending them to STDIN.
 *    sqlite3 passwordsafe.db < myscript.sql
 * This database can be recreated (to clean it up) by running:
 *    sqlite3 passwordsafe.db < dropdb.sql
 *    sqlite3 passwordsafe.db < initdb.sql
 *
 * This is outlined in more detail in api.php, but the Response object
 * has a few methods you will need to use:
 *    - set_http_code -- sets the HTTP response code (an integer)
 *    - success       -- sets a success status message
 *    - failure       -- sets a failure status message
 *    - set_data      -- returns arbitrary data to the client (in json)
 *    - set_cookie    -- sets an HTTP-only cookie on the client that
 *                       will automatically be returned with every 
 *                       subsequent request.
 *    - delete_cookie -- tells the client to delete a cookie.
 *    - set_token     -- passes a token (via data, not headers) to the
 *                       client that will automatically be returned with 
 *                       every subsequent request.
 *
 * A few things you will need to know to succeed:
 * ---------------------------------------------------
 * To get the current date and time in a format the database expects:
 *      $now = new DateTime();
 *      $now->format(DateTimeInterface::ISO8601);
 *
 * To get a date and time 15 minutes in the future (for the database):
 *      $now = new DateTime();
 *      $interval = new DateInterval("PT15M");
 *      $now->add($interval)->format(DateTimeInterface::ISO8601);
 *
 * Notice that, like JavaScript, PHP is loosely typed.  A common paradigm in
 * PHP is for a function to return some data on success or false on failure.
 * Care should be taken with these functions to test for failure using === 
 * (as in, if($result !== false ) {...}) because not using === or !== may 
 * result in unexpected ceorcion of a valid response (0) to false.
 * 
 *****************************************************************************/


/**
 * Performs any resource agnostic preflight validation and can set generic response values.
 * If the request fails any checks, preflight should return false and set appropriate
 * HTTP response codes and a failure message.  Returning false will prevent the requested
 * resource from being called.
 */
function preflight(&$request, &$response, &$db) {
  // check if sessionId is set
  $session_id = $request->token("sessionId");

  if (!empty($session_id)) {
    if (is_web_session_valid($session_id)) {
      $response->set_http_code(200);
      $response->success("Request OK");
      log_to_console("OK");
      return true;
    } else {
      $response->set_http_code(401);
      $response->set_token("sessionId", "");
      $response->failure("Your session has expired.");
      log_to_console("Web session expired");
      return false;
    }
  } else {
    // check client origin
    $client_origin = $request->header("Origin");

    if (!empty($client_origin)) {
      $recognized_origins = ['http://localhost:8000'];
      // check if origin belongs to list of recognized origins
      if (in_array($client_origin, $recognized_origins)) {

        // create new web session with IP as unique identifier until client has authenticated; give them at most 5 mins (consider initializing # login attempts)
        $client_ip = $request->client_ip();
        $db = new PDO("sqlite:passwordsafe.db");
        $stmt = $db->prepare("INSERT INTO web_session (sessionId, expires) VALUES (:ssn, datetime('now', '+5 minutes')) ON CONFLICT(sessionId) DO UPDATE SET expires = datetime('now', '+5 minutes')");
        $stmt->execute(['ssn' => $client_ip]);
        $stmt = null;

        $db = null;

        $response->set_http_code(200);
        $response->set_token("sessionId", $client_ip);
        $response->success("Request OK");
        log_to_console("OK");
        return true;
      }
    }
  }
  $response->set_http_code(403);
  $response->failure("You don't have permission to access / on this server.");
  log_to_console("The client is not authorized to perform this operation.");
  return true;
}

/**
 * Tries to sign up the username with the email and password.
 * The username and email must be unique and valid, and the password must be valid.
 * Note that it is fine to rely on database constraints.
 */
function signup(&$request, &$response, &$db) {
  $username = $request->param("username"); // The requested username from the client
  $password = $request->param("password"); // The requested password from the client
  $email    = $request->param("email");    // The requested email address from the client
  $fullname = $request->param("fullname"); // The requested full name from the client

  // check if username or email exists
  $db = new PDO("sqlite:passwordsafe.db");
  $stmt = $db->prepare("SELECT count(*) FROM user where username = :uname or email = :id");
  $stmt->execute(['uname' => $username, 'id' => $email]);
  $count = $stmt->fetch(PDO::FETCH_COLUMN);
  $stmt = null;

  if (!$count) {
    // unique username and email combination - prepare to encrypt parameters before insertion

    // generate salt for password hash
    $salt = bin2hex(random_bytes(32));

    // store password + salt in user_login table
    $stmt = $db->prepare('INSERT INTO user_login (username, salt) VALUES (:uname, :slt)');
    $stmt->execute(['uname' => $username, 'slt' => $salt]);
    $stmt = null;

    // create user record in user table
    $hash = openssl_digest($password . $salt, "SHA256");
    $stmt = $db->prepare("INSERT INTO user (username, passwd, email, fullname, valid, modified) VALUES (:uname, :pw, :id, :fname, :vd, datetime('now'))");
    $stmt->execute(['uname' => $username, 'pw' => $hash, 'id' => $email, 'fname' => $fullname, 'vd' => false]);
    $stmt = null;
    
    $db = null;

    // Respond with a message of success.
    $response->set_http_code(201); // Created
    $response->success("Account created.");
    log_to_console("Account created.");

    return true;
  }

  // user exists

  $db = null;

  // Respond with a message of error.
  $response->set_http_code(409); // Conflict
  $response->failure("The entered username or email already exists.");
  log_to_console("Account could not be created.");

  return false;
}


/**
 * Handles identification requests.
 * This resource should return any information the client will need to produce 
 * a log in attempt for the given user.
 * Care should be taken not to leak information!
 */
function identify(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username

  // fetch salt
  $db = new PDO("sqlite:passwordsafe.db");
  $stmt = $db->prepare("SELECT salt FROM user_login where username = ?");
  $stmt->execute(array($username));
  $salt = $stmt->fetch(PDO::FETCH_COLUMN);
  $stmt = null;

  // if salt exists then user is in the table
  if (!empty($salt)) {

    // generate and store challenge
    $challenge = bin2hex(random_bytes(random_int(64, 127)));
    $stmt = $db->prepare("UPDATE user_login SET challenge = ?, expires = datetime('now', '+10 seconds') WHERE username = ?");
    $stmt->execute([$challenge, $username]);
    $stmt = null;
    $db = null;

    $response->set_http_code(200);
    $response->success("Successfully identified user.");
    $response->set_data("salt", $salt);
    $response->set_data("challenge", $challenge);
    log_to_console("Identified user.");

    return true;
  }
  
  $db = null;
  $response->set_http_code(404);
  $response->failure("The entered username or password is incorrect.");
  log_to_console("Failed to identify.");
  return false;
}

/**
 * Handles login attempts.
 * On success, creates a new session.
 * On failure, fails to create a new session and responds appropriately.
 */
function login(&$request, &$response, &$db) {
  $username = $request->param("username"); // The username with which to log in
  $client_ciphertext = $request->param("ciphertext"); // The ciphertext (encrypted challenge)
  $initialization_vector = hex2bin($request->param("initializationVector")); // change to binary data
  $web_session_id = $request->token("sessionId");

  $db = new PDO("sqlite:passwordsafe.db");
  $stmt = $db->prepare("SELECT passwd, challenge, fullname, expires FROM user NATURAL JOIN user_login where username = ?");
  $stmt->execute(array($username));
  $result = $stmt->fetch(PDO::FETCH_ASSOC);
  $stmt = null;

  // identify call always precedes login so if this function is called the user definitely exists
  $key = $result['passwd'];
  $challenge = $result['challenge'];
  $fullname = $result['fullname'];
  $challenge_expiry = $result['expires'];

  // hex encoded ciphertext since js encrypt function returns hex-encoded ciphertext
  $server_ciphertext = bin2hex(openssl_encrypt($challenge, "AES-256-CBC", hex2bin($key), OPENSSL_RAW_DATA, $initialization_vector));
  $now = new DateTime();

  if (strcmp($server_ciphertext, $client_ciphertext) == 0 && $challenge_expiry < $now) {

    // create session lasting 10 mins
    $session_id = bin2hex(random_bytes(32));
    $stmt = $db->prepare("INSERT INTO user_session (sessionid, username, expires) VALUES (:ssn, :uname, datetime('now', '+10 minutes'))");
    $stmt->execute(['ssn' => $session_id, 'uname' => $username]);
    $stmt = null;

    // update web session so session id from user_session = web_session
    $stmt = $db->prepare("UPDATE web_session SET sessionid = :user_ssn, expires = datetime('now', '+10 minutes') WHERE sessionid = :web_ssn");
    $stmt->execute(['user_ssn' => $session_id, 'web_ssn' => $web_session_id]);
    $stmt = null;

    // update user to validate account given user has logged in after creation
    $stmt = $db->prepare("UPDATE user SET valid = :vd, modified = datetime('now') WHERE username = :un");
    $stmt->execute(['vd' => true, 'un' => $username]);
    $stmt = null;

    $db = null;

    $response->set_http_code(200); // OK
    $response->set_token("sessionId", $session_id); // send client copy of session id to make subsequent requests with
    $response->set_data("fullname", $fullname);
    $response->success("Successfully logged in.");
    log_to_console("Session created.");
    return true;
  }

  $db = null;

  $response->set_http_code(401);
  $response->failure("The entered username or password is incorrect.");
  log_to_console("Failed to authenticate.");
  return false;
}


/**
 * Returns the sites for which a password is already stored.
 * If the session is valid, it should return the data.
 * If the session is invalid, it should return 401 unauthorized.
 */
function sites(&$request, &$response, &$db) {
  // only care about user session here
  $session_id = $request->token("sessionId");
  if (is_user_session_valid($session_id)) {
    $db = new PDO("sqlite:passwordsafe.db");
    $stmt = $db->prepare("SELECT siteid, site FROM user_safe NATURAL JOIN user_session where sessionid = ?");
    $stmt->execute(array($session_id));
    $sites = [];
    $site_ids = [];

    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
      array_push($site_ids, $row['siteid']);
      array_push($sites, $row['site']);
    }
    
    $stmt = null;

    $db = null;

    $response->set_data("siteids", $site_ids);
    $response->set_data("sites", $sites);
    $response->set_http_code(200);
    $response->success("Sites with recorded passwords.");
    log_to_console("Found and returned sites");
    return true;
  }

  $response->set_http_code(401);
  $response->set_token("sessionId", "");
  $response->failure("Your session has expired.");
  log_to_console("User session expired");
  return false;
}

/**
 * Saves site and password data when passed from the client.
 * If the session is valid, it should save the data, overwriting the site if it exists.
 * If the session is invalid, it should return 401 unauthorized.
 */
function save(&$request, &$response, &$db) {
  $site_id      = $request->param("siteid");
  $site         = $request->param("site");
  $site_user    = $request->param("siteuser");
  $site_passwd  = $request->param("sitepasswd");
  $site_iv      = $request->param("siteiv");

  // only care about user session here
  $session_id = $request->token("sessionId");
  if (is_user_session_valid($session_id)) {

    // check if site id exists
    $stmt = $db->prepare("SELECT count(*) FROM user_safe where siteid = ?");
    $stmt->execute(array($site_id));
    $count = $stmt->fetch(PDO::FETCH_COLUMN);
    $stmt = null;

    if (!$count) {
      // site id doesn't exist - INSERT new record
      // get username from session id
      $db = new PDO("sqlite:passwordsafe.db");
      $stmt = $db->prepare("SELECT username FROM user_session where sessionid = ?");
      $stmt->execute(array($session_id));
      $username = $stmt->fetch(PDO::FETCH_COLUMN);
      $stmt = null;

      $stmt = $db->prepare("INSERT INTO user_safe (username, site, siteuser, sitepasswd, siteiv, modified) VALUES (:un, :st, :stuser, :stpwd, :stiv, datetime('now'))");
      $stmt->execute(['un' => $username, 'st' => $site, 'stuser' => $site_user, 'stpwd' => $site_passwd, 'stiv' => $site_iv]);
      log_to_console("Inserted site data");
    } else {
      // site id exists - UPDATE existing record
      $stmt = $db->prepare("UPDATE user_safe SET siteuser = :stuser, sitepasswd = :stpwd, siteiv = :stiv, modified = datetime('now') WHERE siteid = :stid");
      $stmt->execute(['stuser' => $site_user, 'stpwd' => $site_passwd, 'stiv' => $site_iv, 'stid' => $site_id]);
      log_to_console("Updated site data");
    }

    $stmt = null;

    $db = null;

    $response->set_http_code(200);
    $response->success("Save to safe succeeded.");
    log_to_console("Successfully saved site data");
    return true;
  }

  $response->set_http_code(401);
  $response->set_token("sessionId", "");
  $response->failure("Your session has expired.");
  log_to_console("User session expired");
  return false;
}

/**
 * Gets the data for a specific site and returns it.
 * If the session is valid and the site exists, return the data.
 * If the session is invalid return 401, if the site doesn't exist return 404.
 */
function load(&$request, &$response, &$db) {
  $session_id = $request->token("sessionId");
  $site_id = $request->param("siteid");

  if (is_user_session_valid($session_id)) {
    $db = new PDO("sqlite:passwordsafe.db");
    $stmt = $db->prepare("SELECT site, siteuser, sitepasswd, siteiv FROM user_safe where siteid = ?");
    $stmt->execute(array($site_id));
    $result = $stmt->fetch(PDO::FETCH_ASSOC);
    $stmt = null;

    $site = $result['site'];
    $site_user = $result['siteuser'];
    $site_passwd = $result['sitepasswd'];
    $site_iv = $result['siteiv'];

    // $response->set_data("siteid", $site_id);
    $response->set_data("site", $site);
    $response->set_data("siteuser", $site_user);
    $response->set_data("sitepasswd", $site_passwd);
    $response->set_data("siteiv", $site_iv);
    $response->set_http_code(200);
    $response->success("Site data retrieved.");
    log_to_console("Successfully retrieved site data");

    return true;
  }

  $response->set_http_code(401);
  $response->set_token("sessionId", "");
  $response->failure("Your session has expired.");
  log_to_console("User session expired");
  return false;

}

/**
 * Logs out of the current session.
 * Delete the associated session if one exists.
 */
function logout(&$request, &$response, &$db) {
  $session_id = $request->token("sessionId"); // terminate session given id

  if (!empty($session_id)) {
    // delete from both web and user session
    $db = new PDO("sqlite:passwordsafe.db");
    $stmt = $db->prepare("DELETE FROM user_session where sessionid = ?");
    $stmt->execute(array($session_id));
    $stmt = null;

    $stmt = $db->prepare("DELETE FROM web_session where sessionid = ?");
    $stmt->execute(array($session_id));
    $stmt = null;

    $response->set_http_code(200);
    $response->set_token("sessionId", "");
    $response->success("Successfully logged out.");
    log_to_console("Logged out");

    return true;
  }

  $response->set_http_code(401);
  $response->failure("Successfully logged out.");
  log_to_console("Client requested logout resource while unauthenticated.");

  return true;
}

// my utility functions

function is_user_session_valid($session_id) {
  $db = new PDO("sqlite:passwordsafe.db");
  $stmt = $db->prepare("SELECT count(*) FROM user_session WHERE sessionid = ? and expires > datetime('now')");
  $stmt->execute(array($session_id));
  $count = $stmt->fetch(PDO::FETCH_COLUMN);
  
  $stmt = null;

  if ($count > 0) {
    $db = null;
    return true;
  }

  // delete from both web and user session
  $stmt = $db->prepare("DELETE FROM web_session where sessionid = ?");
  $stmt->execute(array($session_id));
  $stmt = null;

  $stmt = $db->prepare("DELETE FROM user_session where sessionid = ?");
  $stmt->execute(array($session_id));
  $stmt = null;

  $db = null;

  return false;
}

function is_web_session_valid($session_id) {
  $db = new PDO("sqlite:passwordsafe.db");
  $stmt = $db->prepare("SELECT count(*) FROM web_session WHERE sessionid = ? and expires > datetime('now')");
  $stmt->execute(array($session_id));
  $count = $stmt->fetch(PDO::FETCH_COLUMN);
  
  $stmt = null;

  if ($count > 0) {
    $db = null;
    return true;
  }

  // delete from web session
  $stmt = $db->prepare("DELETE FROM web_session where sessionid = ?");
  $stmt->execute(array($session_id));
  $stmt = null;

  $db = null;

  return false;
}
?>