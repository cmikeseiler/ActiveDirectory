<?php
namespace ActiveDirectory;

use Exception;
/**
 * Active Directory package; includes connector and common functions
 * for users and groups.
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
class ActiveDirectory
{
	protected $ad_host		= AD_HOST;
	protected $ad_port		= AD_PORT;
	protected $ad_user		= AD_USER;
	protected $ad_pass		= AD_PASS;
	protected $ad_basedn	= AD_BASEDN;
	public $adCx			= null;
	public $bindCx			= null;
	
	/* constructor - generates the connection to the server or returns an error if failed
	 * 
	 * params are retrieved from the configuration file constants
	 */
	public function __construct()
	{
		try {
			$this->adCx = ldap_connect($this->ad_host,$this->ad_port);
			ldap_set_option($this->adCx, LDAP_OPT_DEBUG_LEVEL, 1);
			ldap_set_option($this->adCx, LDAP_OPT_PROTOCOL_VERSION, 3);
			$this->bindCx = self::bind();
		} catch (\Exception $e) {
			$error = $e->getMessage();
		}
		return isset($this->adCx) ? $this->adCx : $error;
	}
	
	/*
	 * bind() - function that binds the active directory user to the server or returns an error if failed
	 * 
	 * @return boolean|string Returns boolean true or string error if unable to bind 
	 */
	public function bind()
	{
		$this->bindCx = ldap_bind($this->adCx,$this->ad_user,$this->ad_pass);
		$errorNo = ldap_errno($this->adCx);
		$errorDesc = ldap_error($this->adCx);
		$error = $errorNo.": ".$errorDesc;
		return !empty($this->bindCx) ? $this->bindCx : $error;
	}

	/*
	 * getUnixTime - converts the Microsoft Timestamp into a Unix Timestamp; 
	 * See http://support.microsoft.com/kb/555936 for more details
	 * @param int $ts Timestamp from the AD Server
	 * @return int $uts Unix Timestamp converted
	*/
	public function getUnixTime($ts)
	{
		$uts = (($ts/10000000) - 11644473600);
		return $uts;
	}

	/*
	 * getBase - return the basedn to keep it protected
	 */
	public function getBase()
	{
		return $this->ad_basedn;
	}
}
