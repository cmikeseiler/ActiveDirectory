<?php
namespace ActiveDirectory; 

use Exception;
/**
 * Active Directory Group Class - provides common group functions:
 * add, remove, modify, search
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
 * @link       http://michaelseiler.net/projects-code/activedirectory/
 */
class Group extends ActiveDirectory implements ActiveDirectoryInterface
{
        /*
         * search - does a search for the group in the Active Directory
         * @param string $groupname The name of the group to search for
	 *
         * @return mixed|boolean Returns the group DN or false if nothing found
         */

	public function search($groupname)
	{
		$ldap_search_filter = "(cn=$groupname)";
		$ldap_search = ldap_search($this->adCx,"$this->ad_basedn","$ldap_search_filter");
		if($ldap_search) {
			$ldap_group_results = ldap_get_entries($this->adCx, $ldap_search);
			if($ldap_group_results['count'] != 0) {
				$ldap_group = ldap_first_entry($this->adCx, $ldap_search);
				$ldap_groupDN = ldap_get_dn($this->adCx,$ldap_group);
				return $ldap_groupDN;
			} else {
				return false;
			}
		}
	}
	
	/*
	 * modify - renames an AD Group to a new name 
	 * @param string $groupname The current name of the AD group
	 * @param string $newname The new name we wish to give to the group
	 *
	 * @return boolean|string True if successful, or error on failure 
	 */
	public function modify($groupname,$newname)
	{
		$new = "cn=".$newname;
                $newParent = "ou=groups,".$this->ad_basedn;
		$groupDN = self::search($groupname);
                // NOW DO THE ACTUAL CHANGE
                if(ldap_rename($this->adCx,$groupDN,$new,$newParent,true) == true) {
			return true;
                } else {
			$errorNo = ldap_errno($this->adCx);
			$errorDesc = ldap_error($this->adCx);
			$error = "Error #".$errorNo.": ".$errorDesc;
			return $error;
                }
	}

	/*
	 * add - adds a security group to the Active Directory; see the following for group types:
	 * http://technet.microsoft.com/en-us/library/dn579255.aspx
	 * 
	 * If you need to add more attributes in your groupData array, you can find a list here:
	 * http://msdn.microsoft.com/en-us/library/ms675729%28v=vs.85%29.aspx
	 *
	 * @param mixed $groupData Array of groupdata containing as little or as much as needed to create a user
	 *	should be in key=>value mapped array format
	 *	--Required Element--
	 * 	1) groupname - the name of the group
	 *	--Optional Element--
	 *	1) groupdesc - a description of the group
	 *
	 * @return mixed Boolean True if successful, and the LDAP errors if failed
	 */
	public function add($groupData)
	{
		$entry = array();
		if(!array_key_exists("groupname",$groupData)) {
			return false;
		} else {
			$groupName = $groupData['groupname'];
			$groupDesc = isset($groupData['groupdesc']) ? $groupData['groupdesc'] : null;
			// Generate the Group DN
			$dn = "CN=".$groupName.",OU=groups,".$this->ad_basedn;
			// Build the entry array
			$entry["cn"] = "$groupName";
			$entry["sAMAccountName"] = $groupName;
			if(isset($groupDesc)) {
				$entry["Description"] = $groupDesc;
			}
	                $entry["objectclass"][0] = "top";
	                $entry["objectclass"][1] = "group";
			// create group of type global and security
			// http://msdn.microsoft.com/en-us/library/ms675935(v=vs.85).aspx
			// group type value of global (2) and group type value of security (2147483648)
			// are added to give a value of "2147483650"
			$entry['groupType'] = "2147483650";
			if(ldap_add($this->adCx,$dn,$entry)) {
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
	 * remove - deletes a group from the Active Directory
	 * @param string $groupname - The group name
	 * 
	 * @return boolean|mixed True if success, and error messages if failure
	 */
	public function remove($groupname)
	{
                $groupDN = self::search($groupname);
		if(ldap_delete($this->adCx,$groupDN) == true) {
			return true;
		} else {
			$errorNo = ldap_errno($this->adCx);
			$errorDesc = ldap_error($this->adCx);
			$error = "Error #".$errorNo.": ".$errorDesc;
			return $error;
		}
	}
}
