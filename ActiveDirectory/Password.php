<?php
namespace ActiveDirectory; 

use Exception;
/**
 * Active Directory Password class - provides functions to reset a password
 * and generate a new password according to default Active Directory rules
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
class Password
{
	private $user = null;

	public function __construct(\ActiveDirectory\User $user)
	{
		$this->user = $user;
	}
	
	/*
	 * resetPassword - (re)sets the password for a user
	 * @param string $username The sAMAcccountName of the user in question
	 * @param string $password Optional string sent to the function for reset
	 * 
	 * @return boolean|string True if success (user changed pass)/ False if error
	 * 	returns generated password if reset by admin
	 */
	public function resetPassword($username, $password = null)
	{
		$newPassword = (isset($password)) ? $password : self::generatePassword();
		$mods['unicodePwd'] = self::encodePwd($newPassword);
		// making the assumption here that if a password is sent, the user sent it
		if(!isset($password)) {
			// We need to force a user to change their password at next logon, 
			// so we set the pwdLastSet attribute to zero (0).
			// See: http://msdn.microsoft.com/en-us/library/aa746510(v=vs.85).aspx
			$mods['pwdlastset'] = (int)0;
		}
		if($this->user->modify($username,$mods)) {
			if(!isset($password)) {
				return $newPassword;
			} else {
				return true;
			}
		} else {
			return false;
		}	
	}
	
	/*
	 * encodePwd - function to encode the password in unicode; According to Microsoft, it seems that 
	 * when using LDP.EXE, only a UTF16-LE is needed: http://msdn.microsoft.com/en-us/library/cc223248.aspx
	 * @param string $new_password The password to encode
	 * 
	 * @return string $encodedPwd The encoded password
	 */
	private function encodePwd($new_password) {
		$newpass = '';
		$new_password = "\"".$new_password."\"";
		$len = strlen($new_password);
		for ($i = 0; $i < $len; $i++) {
				$newpass .= "{$new_password{$i}}\000";
		}
		return $newpass;
	}

	/*
	 * generatePassword() - function that generates a random password that conforms to AD demands (defaults)
	 * @return string newPass - new password that was generated
	 */
	private function generatePassword()
	{
		$uppercase = array("A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T"
			,"U","V","W","X","Y","Z");
		$lowercase = array("a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t"
                        ,"u","v","w","x","y","z");
		$symbols = array("~","!","@","#","$","%","^","&","*","_","-","|","("
			,")","{","}","[","]",":",";","<",">","?","/");
		
		$cases = 26;
		$syms = count($symbols) - 1;
		// set minimum length - if you change it, make it divisible by 4
		$minLength = 8;
		// now iterate and give a sufficiently weird password
		$generatedPass = "";
		for($i = 0; $i < ($minLength/4); $i++) {
			$randCases = rand($i,$cases);
			$randNums = rand($i,9);
			$randSyms = rand($i,$syms);
			$generatedPass .= $uppercase[$randCases];
			$generatedPass .= $lowercase[$randCases];
			$generatedPass .= $randNums;
			$generatedPass .= $symbols[$randSyms];
		}
		return $generatedPass;
	}
}
