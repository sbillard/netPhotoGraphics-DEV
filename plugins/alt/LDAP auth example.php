<?php

/*
 * This is an example script to link ZenPhoto20 to an LDAP server for user verification
 * for posix-style users and groups.
 *
 * Note: Assumes user_groups plugin is enabled and a group named as defined in ZP_USERS is setup. LDAP users
 * will be defacto members of that group. Assumes that no standard ZenPhoto20 user has a database
 * record ID greater than the id number returned by the LDAP server.
 *
 * To activate rename the script to "class-auth.php" and change the LDAP defines as appropriate
 */

define('LDAP_DOMAIN', 'localhost');
define('LDAP_BASEDN', 'dc=rpi,dc=swinden,dc=local');
define('LDAP_GROUP', 'users');

define('ZP_GROUP', 'users');
define('ZP_PASS', 'LDAP');


require_once(SERVERPATH . '/' . ZENFOLDER . '/lib-auth.php');

class Zenphoto_Authority extends _Authority {

	function handleLogon() {
		global $_zp_current_admin_obj;
		$user = sanitize(@$_POST['user'], 0);
		$password = sanitize(@$_POST['pass'], 0);
		$loggedin = false;

		$ad = self::ldapInit(LDAP_DOMAIN);
		$userdn = "uid={$user},ou=Users," . LDAP_BASEDN;

		// We suppress errors in the binding process, to prevent a warning
		// in the case of authorisation failure.
		$bindResult = @ldap_bind($ad, $userdn, $password);
		if ($bindResult) {
			$group = self::ldapSingle($ad, '(cn=' . LDAP_GROUP . ')', 'ou=Groups,' . LDAP_BASEDN, array('memberUid'));
			if ($group) {
				$members = $group['memberuid'];
				unset($members['count']);
				$isMember = in_array($user, $members, true);

				if ($isMember) {
					echo "You're authorized as " . $userdn;

					$userData = self::ldapUser($ad, "(uid={$user})");
					if ($userData) {
						$_zp_current_admin_obj = self::setupUser($userData);
						$loggedin = $_zp_current_admin_obj->getRights();
						self::logUser($_zp_current_admin_obj);
					}
				} else {
					echo 'Authorization failed';
				}
				ldap_unbind($ad);
			} else {
				echo 'no LDAP group';
			}
		} else {
			echo 'Could not bind to LDAP.';
		}

		if ($loggedin) {
			return $loggedin;
		} else {
			// If the LDAP authorisation failed we try the standard logon, e.g.
			// for a master administrator.
			return parent::handleLogon();
		}
	}

	function checkAuthorization($authCode, $id) {
		global $_zp_current_admin_obj;
		$ad = self::ldapInit(LDAP_DOMAIN);
		$userData = self::ldapUser($ad, "(uidNumber={$id})");
		ldap_unbind($ad);
		if ($userData) {
			$goodAuth = Zenphoto_Authority::passwordHash($userData['uid'][0], 'LDAP');
			if ($authCode == $goodAuth) {
				$_zp_current_admin_obj = self::setupUser($userData);
				return $_zp_current_admin_obj->getRights();
			}
		}
		return parent::checkAuthorization($authCode, $id);
	}

	static function setupUser($userData) {
		$user = $userData['uid'][0];
		$id = $userData['uidnumber'][0];
		$name = $userData['cn'][0];
		if (isset($userData['email'][0])) {
			$adminObj->setEmail($userData['email'][0]);
		}

		$adminObj = Zenphoto_Authority::newAdministrator('');
		$adminObj->setID($id);
		$adminObj->transient = true;
		$this->addOtherUser($adminObj);

		$adminObj->setUser($user);
		$adminObj->setName($name);
		$adminObj->setPass(ZP_PASS);

		if (class_exists('user_groups')) {
			user_groups::merge_rights($adminObj, array(ZP_GROUP));
			$rights = $adminObj->getRights() ^ USER_RIGHTS;
			$adminObj->setRights($rights);
		} else {
			$adminObj->setRights(DEFAULT_RIGHTS ^ USER_RIGHTS);
		}
		return $adminObj;
	}

	/*
	 * This function searches in LDAP tree ($ad -LDAP link identifier),
	 * starting under the branch specified by $basedn, for a single entry
	 * specified by $filter, and returns the requested attributes or null
	 * on failure.
	 */

	static function ldapSingle($ad, $filter, $basedn, $attributes) {
		$result = ldap_search($ad, $basedn, $filter, $attributes);
		if ($result === FALSE) {
			return null;
		}
		$entries = ldap_get_entries($ad, $result);
		if ($entries['count'] != 0) {
			return $entries[0];
		} else {
			return null;
		};
	}

	static function ldapUser($ad, $filter) {
		return self::ldapSingle($ad, $filter, 'ou=Users,' . LDAP_BASEDN, array('uid', 'uidnumber', 'cn', 'email'));
	}

	static function ldapInit($domain) {
		$ad = ldap_connect("ldap://{$domain}") or die('Could not connect to LDAP server.');
		ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
		ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);
		return $ad;
	}

}

class Zenphoto_Administrator extends _Administrator {

	function setID($id) {
		$this->set('id', $id);
	}

	function setPass($pwd) {
		$hash = parent::setPass($pwd);
		$this->set('passupdate', NULL);
		return $hash;
	}

}

?>
