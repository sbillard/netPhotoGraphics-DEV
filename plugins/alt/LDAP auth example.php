<?php
/*
 * This is an example script to link ZenPhoto20 to an LDAP server for user verification.
 * It assumes that your LDAP server contains posix-style users and groups.
 *
 * To activate rename the script to "class-auth.php" and set LDAP configuration
 * options on the admin/security tab as appropriate.
 *
 * @author Stephen Billard (sbillard), (ariep)
 *
 * @package alt
 * @subpackage users
 */

define('LDAP_DOMAIN', getOption('ldap_domain'));
define('LDAP_BASEDN', getOption('ldap_basedn'));
define('LDAP_ID_OFFSET', getOption('ldap_id_offset')); //	number added to LDAP ID to insure it does not overlap any ZP admin ids
define('LDAP_READER_USER', getOption('ldap_reader_user'));
define('LDAP_REAER_PASS', getOption('ldap_reader_pass'));
$_LDAPGroupMap = getSerializedArray(getOption('ldap_group_map'));

require_once(SERVERPATH . '/' . ZENFOLDER . '/lib-auth.php');
if (extensionEnabled('user_groups')) {
	require_once(SERVERPATH . '/' . ZENFOLDER . '/' . PLUGIN_FOLDER . '/user_groups.php');
}

class Zenphoto_Authority extends _Authority {

	function getOptionsSupported() {
		setOptionDefault('ldap_id_offset', 100000);
		$options = parent::getOptionsSupported();
		$ldapOptions = array(
						gettext('LDAP domain')								 => array('key'		 => 'ldap_domain', 'type'	 => OPTION_TYPE_TEXTBOX,
										'order'	 => 1,
										'desc'	 => gettext('Domain name of the LDAP server')),
						gettext('LDAP base dn')								 => array('key'		 => 'ldap_basedn', 'type'	 => OPTION_TYPE_TEXTBOX,
										'order'	 => 1.1,
										'desc'	 => gettext('Base DN strings for the LDAP searches.')),
						gettext('ID offset for LDAP usersids') => array('key'		 => 'ldap_id_offset', 'type'	 => OPTION_TYPE_NUMBER,
										'order'	 => 1.4,
										'desc'	 => gettext('This number is added to the LDAP <em>userid</em> to insure that there is no overlap to ZenPhoto20 <em>userids</em>.')),
						gettext('LDAP reader user')						 => array('key'		 => 'ldap_reader_user', 'type'	 => OPTION_TYPE_TEXTBOX,
										'order'	 => 1.2,
										'desc'	 => gettext('User name for LDAP searches. If empty the searches will be anonymous.')),
						gettext('LDAP reader password')				 => array('key'		 => 'ldap_reader_pass', 'type'	 => OPTION_TYPE_PASSWORD,
										'order'	 => 1.3,
										'desc'	 => gettext('User password for LDAP searches.'))
		);
		if (extensionEnabled('user_groups')) {
			$ldapOptions[gettext('LDAP Group map')] = array('key'		 => 'ldap_group_map_custom', 'type'	 => OPTION_TYPE_CUSTOM,
							'order'	 => 1.5,
							'desc'	 => gettext('Mapping of LDAP groups to ZenPhoto20 groups'));
		}
		return array_merge($ldapOptions, $options);
	}

	function handleOption($option, $currentValue) {
		global $_zp_authority;
		if ($option == 'ldap_group_map_custom') {
			$groups = $_zp_authority->getAdministrators('groups');
			$ldap = getSerializedArray(getOption('ldap_group_map'));
			if (empty($groups)) {
				echo gettext('No groups or templates are defined');
			} else {
				?>
				<dl>
					<?php
					foreach ($groups as $group) {
						if (array_key_exists($group['user'], $ldap)) {
							$ldapgroup = $ldap[$group['user']];
						} else {
							$ldapgroup = $group['user'];
						}
						echo '<dh><input type="textbox" name="LDAP_group_for_' . $group['id'] . '" value="' . html_encode($ldapgroup) . '"></dh><dt>' . html_encode($group['user']) . '</dt>';
					}
					?>
				</dl>
				<?php
			}
		} else {
			parent::handleOption($option, $currentValue);
		}
	}

	function handleOptionSave($themename, $themealbum) {
		global $_zp_authority;
		$groups = $_zp_authority->getAdministrators('groups');
		if (!empty($groups)) {
			foreach ($_POST as $key => $v) {
				if (strpos($key, 'LDAP_group_for_') !== false) {
					$ldap[$groups[substr($key, 15)]['user']] = $v;
				}
			}
			setOption('ldap_group_map', serialize($ldap));
		}
		parent::handleOptionSave($themename, $themealbum);
	}

	function handleLogon() {
		global $_zp_current_admin_obj;
		$user = sanitize(@$_POST['user'], 0);
		$password = sanitize(@$_POST['pass'], 0);
		$loggedin = false;

		$ad = self::ldapInit(LDAP_DOMAIN);
		$userdn = "uid={$user},ou=Users," . LDAP_BASEDN;

		// We suppress errors in the binding process, to prevent a warning
		// in the case of authorisation failure.
		if (@ldap_bind($ad, $userdn, $password)) { //	valid LDAP user
			self::ldapReader();
			$userData = array_change_key_case(self::ldapUser($ad, "(uid={$user})"), CASE_LOWER);
			$userobj = self::setupUser($ad, $userData);
			if ($userobj) {
				$_zp_current_admin_obj = $userobj;
				$loggedin = $_zp_current_admin_obj->getRights();
				self::logUser($_zp_current_admin_obj);
				if (DEBUG_LOGIN) {
					debugLog(sprintf('LDAPhandleLogon: authorized as %1$s->%2$X', $userdn, $loggedin));
				}
			} else {
				if (DEBUG_LOGIN) {
					debugLog("LDAPhandleLogon: no rights");
				}
			}
		} else {
			if (DEBUG_LOGIN) {
				debugLog("LDAPhandleLogon: Could not bind to LDAP");
			}
		}
		@ldap_unbind($ad);
		if ($loggedin) {
			return $loggedin;
		} else {
			// If the LDAP authorisation failed we try the standard logon, e.g. for a master administrator.
			return parent::handleLogon();
		}
	}

	function checkAuthorization($authCode, $id) {
		global $_zp_current_admin_obj;
		if (LDAP_ID_OFFSET && $id > LDAP_ID_OFFSET) { //	LDAP ID
			$ldid = $id - LDAP_ID_OFFSET;
			$ad = self::ldapInit(LDAP_DOMAIN);
			if ($ad) {
				self::ldapReader();
				$userData = self::ldapUser($ad, "(uidNumber={$ldid})");
				if ($userData) {
					$userData = array_change_key_case($userData, CASE_LOWER);
					if (DEBUG_LOGIN) {
						debugLogBacktrace("LDAPcheckAuthorization($authCode, $ldid)");
					}
					$goodAuth = Zenphoto_Authority::passwordHash($userData['uid'][0], serialize($userData));
					if ($authCode == $goodAuth) {
						$userobj = self::setupUser($ad, $userData);
						if ($userobj) {
							$_zp_current_admin_obj = $userobj;
							$rights = $_zp_current_admin_obj->getRights();
						} else {
							$rights = 0;
						}
						if (DEBUG_LOGIN) {
							debugLog(sprintf('LDAPcheckAuthorization: from %1$s->%2$X', $authCode, $rights));
						}
					} else {
						if (DEBUG_LOGIN) {
							debugLog(sprintf('LDAPcheckAuthorization: AuthCode %1$s <> %2$s', $goodAuth, $authCode));
						}
					}
				}
				@ldap_unbind($ad);
			}
		}
		if ($_zp_current_admin_obj) {
			return $_zp_current_admin_obj->getRights();
		} else {
			return parent::checkAuthorization($authCode, $id);
		}
	}

	function validID($id) {
		return $id > LDAP_ID_OFFSET || parent::validID($id);
	}

	static function setupUser($ad, $userData) {
		global $_zp_authority;
		$user = $userData['uid'][0];
		$id = $userData['uidnumber'][0] + LDAP_ID_OFFSET;
		$name = $userData['cn'][0];
		$groups = self::getZPGroups($ad, $user);

		$adminObj = Zenphoto_Authority::newAdministrator('');
		$adminObj->setID($id);
		$adminObj->transient = true;

		if (isset($userData['email'][0])) {
			$adminObj->setEmail($userData['email'][0]);
		}
		$adminObj->setUser($user);
		$adminObj->setName($name);
		$adminObj->setPass(serialize($userData));
		if (class_exists('user_groups')) {
			user_groups::merge_rights($adminObj, $groups, array());
			if (DEBUG_LOGIN) {
				debugLogVar("LDAsetupUser: groups:", $adminObj->getGroup());
			}
			$rights = $adminObj->getRights() & ~ USER_RIGHTS;
			$adminObj->setRights($rights);
		} else {
			$rights = DEFAULT_RIGHTS & ~ USER_RIGHTS;
			$adminObj->setRights(DEFAULT_RIGHTS & ~ USER_RIGHTS);
		}

		if ($rights) {
			$_zp_authority->addOtherUser($adminObj);
			return $adminObj;
		}
		return NULL;
	}

	/*
	 * This function searches in LDAP tree ($ad -LDAP link identifier),
	 * starting under the branch specified by $basedn, for a single entry
	 * specified by $filter, and returns the requested attributes or null
	 * on failure.
	 */

	static function ldapSingle($ad, $filter, $basedn, $attributes) {
		$search = NULL;
		$lfdp = ldap_search($ad, $basedn, $filter, $attributes);
		if ($lfdp) {
			$entries = ldap_get_entries($ad, $lfdp);
			if ($entries['count'] != 0) {
				$search = $entries[0];
			}
		}
		ldap_free_result($lfdp);
		return $search;
	}

	static function ldapUser($ad, $filter) {
		return self::ldapSingle($ad, $filter, 'ou=Users,' . LDAP_BASEDN, array('uid', 'uidNumber', 'cn', 'email'));
	}

	/**
	 * returns an array the user's of ZenPhoto20 groups
	 * @param type $ad
	 */
	static function getZPGroups($ad, $user) {
		global $_LDAPGroupMap;
		$groups = array();
		foreach ($_LDAPGroupMap as $ZPgroup => $LDAPgroup) {
			if (!empty($LDAPgroup)) {
				$group = self::ldapSingle($ad, '(cn=' . $LDAPgroup . ')', 'ou=Groups,' . LDAP_BASEDN, array('memberUid'));
				if ($group) {
					$group = array_change_key_case($group, CASE_LOWER);
					$members = $group['memberuid'];
					unset($members['count']);
					$isMember = in_array($user, $members, true);
					if ($isMember) {
						$groups[] = $ZPgroup;
					}
				}
			}
		}
		return $groups;
	}

	static function ldapInit($domain) {
		if ($domain) {
			if ($ad = ldap_connect("ldap://{$domain}")) {

				ldap_set_option($ad, LDAP_OPT_PROTOCOL_VERSION, 3);
				ldap_set_option($ad, LDAP_OPT_REFERRALS, 0);
				return $ad;
			} else {
				zp_error(gettext('Could not connect to LDAP server.'));
			}
		}
		return false;
	}

	/**
	 * login the ldapReader user if defined
	 */
	static function ldapReader() {
		if (LDAP_READER_USER) {
			if (!@ldap_bind($ad, "uid=" . LDAP_READER_USER . ",ou=Users," . LDAP_BASEDN, LDAP_REAER_PASS)) {
				debugLog('LDAP reader authorization failed.');
			}
		}
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
