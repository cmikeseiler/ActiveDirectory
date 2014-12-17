<?php
namespace ActiveDirectory; 

use Exception;
/**
 * Active Directory UserGroup class - provides funcionality for adding
 * and removing a user from a Group, and for verifying user's membership
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
class UserGroup
{
	private $user = null;
	private $group = null;

	public function __construct(\ActiveDirectory\User $user, \ActiveDirectory\Group $group)
	{
		$this->user = $user;
		$this->group = $group;
	}

	/*
	 * addUserToGroup - function to add a user to a group
	 * 
	 * @param string $username The name of the user to modify
	 * @param string $groupname The name of the group to add the user to
	 * 
	 * @return boolean|string True if successful, Error message if failure
	 */
	public function addUserToGroup($username,$groupname)
	{
		$userData = $this->user->search($username);
		$userDN = $userData['dn'];
		$groupDN = $this->group->search($groupname);
		$group_data['member'] = $userDN;
		if(ldap_mod_add($this->user->adCx,$groupDN,$group_data)) {
			return true;
		} else {
			$errorNo = ldap_errno($this->group->adCx);
			$errorDesc = ldap_error($this->group->adCx);
			$error = "Error #".$errorNo.": ".$errorDesc;
			return $error;	
		}
	}

	/*
	 * removeUserFromGroup - function to remove a user from a group
	 *
	 * @param string $username The name of the user to modify
	 * @param string $groupname The name of the group to add the user to
	 * 
	 * @return boolean|string True if successful, Error message if failure
	 */
	public function removeUserFromGroup($username,$groupname)
	{
		$userData = $this->user->search($username);
		$userDN = $userData['dn'];
		$groupDN = $this->group->search($groupname);
		$group_data['member'] = $userDN;
		if(ldap_mod_del($this->group->adCx,$groupDN,$group_data)) {
			return true;
		} else {
			$errorNo = ldap_errno($this->group->adCx);
                        $errorDesc = ldap_error($this->group->adCx);
                        $error = "Error #".$errorNo.": ".$errorDesc;
                        return $error;
		}
	}

	/* 
	 * userInGroup - Checks if a user is in a group, so we don't try to add them to the group again
	 * @param string $username The username of the user in the AD 
	 * @param string $groupname The group name to check for user membership 
	 * 
	 * @return boolean False if not in any group or not of the group we are checking, true otherwise 
	 */
	public function userInGroup($username,$groupname)
	{
		$groupDN = $this->group->search($groupname);
		$filter = "(samaccountname=".$username.")";
		// keep the AD basedn protected
		$baseDN = $this->user->getBase();
		$results = ldap_search($this->user->adCx,$baseDN,$filter,array("memberof"));
		$entries = ldap_get_entries($this->user->adCx, $results);
		$securityGroups = isset($entries[0]['memberof']) ? $entries[0]['memberof'] : null;
		if($securityGroups == null) {
			return false;
		} else {
			if(in_array($groupDN,$securityGroups)) {
				return true;
			} else {
				return false;
			}
		}
	}
}
