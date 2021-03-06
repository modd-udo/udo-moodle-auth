<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Anobody can login with any password.
 *
 * @package auth_udo
 * @author Christopher Seufert <chris@modd.com.au>
 * @copyright 2017 Modd Pty Ltd  {@link https://udo.net.au}
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir . '/authlib.php');

/**
 * Plugin for no authentication.
 */
class auth_plugin_udo extends auth_plugin_base {

  /**
   * Constructor.
   */
  function __construct() {
    $this->authtype = 'udo';
    $this->config = get_config('auth/udo');
  }

  function pre_loginpage_hook() {
    global $USER, $DB;
    if($USER && isset($USER->email)) return;
    if(isset($_REQUEST['MEAUTH']) && $_REQUEST['MEAUTH']) {
      $raw = base64_decode(str_replace(['-','_'],['+','/'],$_REQUEST['MEAUTH']));
      $remoteHash = substr($raw, 0, 20);
      $myHash = hash_hmac('sha1',substr($raw, 20),
        hex2bin($this->config->hmac_secret),true);
      if($myHash != $remoteHash)
        throw new \Exception("Error: Unable to verify login data hash");
      // |".bin2hex($remoteHash).'|'.bin2hex($myHash).'|'.substr($raw,20).'|'.$this->config->hmac_secret);
      $data = explode(';', substr($raw,20),5);
      if(count($data) != 5)
        throw new \Exception("Error: Unable to decode data");
      list($id, $first, $last, $email, $tsData) = $data;
      $first = $first?:"Unknown"; $last = $last?:"Unknown";
      $d = unpack('Nts',$tsData);
      if($d['ts'] + 15 <= time())
        throw new \Exception("Error: URL has expired");
      if($user = $DB->get_record('user', ['username' => "UDO$id"])) {
        $USER = $user;
        $dirty = $USER->firstname != $first || $USER->lastname != $last || $USER->email != $email;
        if($dirty) {
          $USER->firstname = $first;
          $USER->lastname = $last;
          $USER->email = $email;
          $USER->timemodified = time();
          $DB->update_record('user', $USER);
        }
      } else {
        $USER = new stdClass();
        $USER->auth = 'udo';
        $USER->confirmed = 1;
        $USER->username = "UDO$id";
        $USER->idnumber = $id;
        $USER->firstname = $first;
        $USER->lastname = $last;
        $USER->email = $email;
        $USER->timecreated = time();
        $USER->timemodified = time();
        $USER->country = 'AU';
        $USER->id = $DB->insert_record('user', $USER, true);
      }
    }
  }

  function loginpage_hook() {
    if(isset($this->config->login_url) && !empty($this->config->login_url) &&
      !isset($_REQUEST['force']) && !isset($_REQUEST['username'])) {
      header("Location: {$this->config->login_url}", true);
      exit();
    }
  }

  function user_login($username, $password) {
    // Login via login form is not supported
    return false;
  }

  function prevent_local_passwords() {
    return false;
  }

  function is_internal() {
    return true;
  }

  /**
   * Returns the URL for changing the user's pw, or empty if the default can
   * be used.
   *
   * @return moodle_url
   */
  function change_password_url() {
    if(isset($this->config->changepass_url) && !empty($this->config->changepass_url)) {
      return new moodle_url('https://hacsu.asn.au/portal/members-area/My-Details~87');
    }
    return null;
  }

  /**
   * Returns true if plugin can be manually set.
   *
   * @return bool
   */
  function can_be_manually_set() {
    return true;
  }

  /**
   * Prints a form for configuring this authentication plugin.
   *
   * This function is called from admin/auth.php, and outputs a full page with
   * a form for configuring this plugin.
   *
   * @param array $page An object containing all the data for this page.
   */
  function config_form($config, $err, $user_fields) {
    include "config.html";
  }

  /**
   * Processes and stores configuration data for this authentication plugin.
   */
  function process_config($config) {
    set_config('hmac_secret', $config->hmac_secret, 'auth/udo');
    set_config('login_url', $config->login_url, 'auth/udo');
    set_config('changepass_url', $config->changepass_url, 'auth/udo');
    return true;
  }

}


