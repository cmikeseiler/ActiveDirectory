<?php
namespace ActiveDirectory;
/**
 * Active Directory Interface
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
interface ActiveDirectoryInterface
{
	/*
	 * In the case of a User object, the identifier will always be the username (sAMAccountName)
	 * In the case of the Group object, the identifier will always be the group name
	 * Attribute Arrays are those elements that match the appropriate object:
	 * http://msdn.microsoft.com/en-us/library/ms675090(v=vs.85).aspx
	 * Should be in key=>value mapped array
	 */
	public function search($identifier);
	public function modify($identifier, $attributeArray);
	public function add($attributeArray);
	public function remove($identifier);
}
