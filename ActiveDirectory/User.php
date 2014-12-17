<?php
namespace ActiveDirectory; 

use Exception;
/**
 * Active Directory User Class - provides common user functions:
 * add, remove, modify, search, and toggleAccount
 *
 * @author     Michael Seiler <http://michaelseiler.net>
 * @copyright  2014 Michael Seiler
 * @license http://www.gnu.org/licenses/gpl.txt
 * LICENSE: This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * @link       http://michaelseiler.net/ActiveDirectory
 */
class User extends ActiveDirectory implements ActiveDirectoryInterface
{
	/*
	 * search - does a search for the user in the Active Directory
	 * @param string $username The username to search for
	 * @param array $userAttrs An array of attributes we wish to return for the user (e.g. givenName, userPrincipalName, sAMAccountName, pwdLastSet, etc)
	 * For a list of attributes see http://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
	 * @return mixed|boolean Returns an array of the user's DN and the user attributes, false if nothing found
	 */

	public function search($username,$userAttrs = null)
	{
		$userInfo = array();
                $ldap_search_filter = "(sAMAccountName=$username)";
		$userAttrs = (isset($userAttrs)) ? $userAttrs : array("samaccountname");
                // This returns a resultset, but not the specifics
                $ldap_search = ldap_search($this->adCx,"$this->ad_basedn","$ldap_search_filter",$userAttrs);
                if($ldap_search) {
                        $ldap_user_results = ldap_get_entries($this->adCx, $ldap_search);
                        if($ldap_user_results['count'] != 0) {
                                $ldap_user = ldap_first_entry($this->adCx, $ldap_search);
                                $ldap_user_dn = ldap_get_dn($this->adCx,$ldap_user);
				// DN is always required if we want to make changes to a user's record
				$userInfo['dn'] = $ldap_user_dn;
				// Now add the requested Attributes into the mix
				foreach($userAttrs as $attr) {
					$userInfo["$attr"] = isset($ldap_user_results[0]["$attr"][0]) ? $ldap_user_results[0]["$attr"][0] : null;
				}
				return $userInfo;
                        }
                } else {
                        return false;
                }
	}
	
	/*
	 * modify - modifies AD attributes for a user based on DN
	 * @param string $username The username in the AD for the user in question
	 * @param mixed $mods The array of modifications to make to the user's record
	 *
	 * @return boolean|string True if successful, or error on failure 
	 */
	public function modify($username,$mods)
	{
                $userData = self::search($username);
                $userDN = $userData["dn"];
                // NOW DO THE ACTUAL CHANGE
                if(ldap_mod_replace($this->adCx,$userDN,$mods) === false) {
			$errorNo = ldap_errno($this->adCx);
			$errorDesc = ldap_error($this->adCx);
			$error = "Error #".$errorNo.": ".$errorDesc;
			return $error;
                } else {
                        return true;
                }
	}

	/*
	 * add - adds a user to the Active Directory
	 * @param mixed $userData Array of userdata containing as little or as much as needed to create a user
	 *	--Required Element--
	 * 	1) sAMAccountName (Username) - the very bare minimum AD requires to create a user
	 *	--Optional Elements--
	 *	1) userId - This allows you to tack on a userId to the sn, so that AD will generate a unique RDN
	 *	for people with the same first and last name (e.g. John Doe 00012 & John Doe 00013) since it uses
	 *	the display name to generate the RDN.  This has the side-effect of adding the user id to the 
	 *	display name, but if you're using the AD as a web authentication source (CAS/SSO), rather than 
	 *	for computer logins you can create the "Display	Name" from the retrieved elements in search().  
	 *	NOTE: This only works if you actually send SN; this will not work if only sending the username 
	 *	for generation - in which case the username *is* your RDN anyway.  Having the unique RDN allows
	 *	you to change a person's username/email address much easier down the road.
	 *	2) givenName (First Name)
	 *	3) sn (Family Name)
	 *
	 * @return mixed Boolean True if successful, and the LDAP errors if failed
	 */
	public function add($userData)
	{
		$entry = array();
		if(!array_key_exists("samaccountname",$userData)) {
			return false;
		} else {
	                $entry["objectclass"][0] = "top";
	                $entry["objectclass"][1] = "person";
        	        $entry["objectclass"][2] = "organizationalPerson";
                	$entry["objectclass"][3] = "user";
			// Add the key/values into our entry array for creation
			foreach($userData as $key=>$value) {
				$entry["$key"] = $value;
			}
			// Allow the AD to create display name and RDN if first and last exist
			if(isset($entry['givenname']) && isset($entry['sn']) ) {
				$sn = trim($entry['sn']);
				// Generate a uniqueness by adding User ID if it exists
				if(isset($entry['userId'])) {
					$sn = $sn." ".trim($entry['userId']);
					// this key does not exist in AD, so remove after use
					unset($entry['userId']);
				}
				$cn = trim($entry['givenname'])." ".$sn;
				$userCN = "cn=".$cn.",".$this->ad_basedn;
			} else {
			// Create the CN and RDN with samaccountname only - limits modifications
				$cn = trim($entry['samaccountname']);
				$userCN = "cn=".$cn.",".$this->ad_basedn;
			}
			$entry['displayname'] = $cn;
			// 512 indicates that the account is a normal account, and unsuspended
			$entry['useraccountcontrol'] = (int)512;
			// Now the actual work of creating
			if(ldap_add($this->adCx,$userCN,$entry)) {
				return true;
			} else {
				$errorNo = ldap_errno($this->adCx);
		                $errorDesc = ldap_error($this->adCx);
		                $error = "Error #".$errorNo.": ".$errorDesc;
				return $error;
			}
		}
	}
	
	/*
	 * remove - deletes a user from the Active Directory
	 * @param string $username - The sAMAccountName of the user in question
	 * 
	 * @return boolean|mixed True if success, and error messages if failure
	 */
	public function remove($username)
	{
                $userData = self::search($username);
		$userDN = $userData["dn"];
		if(ldap_delete($this->adCx,$userDN) == true) {
			return true;
		} else {
			$errorNo = ldap_errno($this->adCx);
			$errorDesc = ldap_error($this->adCx);
			$error = "Error #".$errorNo.": ".$errorDesc;
			return $error;
		}
	}

	/*
	 * toggleAccount - toggles a user account from enabled to disabled
	 * technically, this is a just a modify() query, but since it is used quite often
	 * added here.
	 * @param string $username The user in the Active Directory
 	 * @param boolean $do True = enable, false = disable
	 * 
	 * @return boolean|string Either true or error from modify()
	 */
	public function toggleAccount($username, $do)
	{
		$toggle = ($do == true) ? "512" : "514";
		$mods['userAccountControl'] = $toggle;
		$result = self::modify($username,$mods);
		if($result == true) {
			return true;
		} else {
			return $result;
		}
	}
}
