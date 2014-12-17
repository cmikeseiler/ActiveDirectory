ActiveDirectory
===============

Active Directory Connector Package in PHP with common methods.

# Synopsis
This is an Active Directory Connector package with common functions for creating, modifying, deleting, and searching for AD Users and Groups.  It also provides some functionality for resetting user passwords, and for adding, removing and searching for a user's group membership.

## User Examples
### User Search
```
$attrs = array("givenname","sn","displayname","mail","userprincipalname",
	"useraccountcontrol","accountexpires","lastlogon","pwdlastset","pwdexpired","samaccountname");
$userResults = $ad->search('gktesterton',$attrs);
```

### Add User
```
$userData = array(
"samaccountname"=>"gktesterton",
"givenname"=>"Tester",
"sn"=>"Testerton",
"mail"=>"gktesterton@yourdomain.com",
"department"=>"Human Resources",
"userId"=>"10013"
);
$new = $ad->add($userData);
```
## Group Examples
Group Search returns the Group DN
```
$groupDN = $ad->search("alumni");
```

## General Usage
Each of the methods will return "true" if successful, and an error from the Active Directory if it failed.  For each method, if you assign the result to a variable, you can display the error message on failure:
```
$result = $ad->methodCall();
if($result !== true) {
	echo "Error: $error.";
}
```

The only difference is the search() methods.  The User search will return an associative array of user data, and the Group search will return the Group's Distinguished Name.

## Installation
This was built to work with PSR-0 autoloading, so if you drop this in your "Vendor" folder in your favorite framework, you should be ready to call the classes.

## Server Setup
Active Directory requires a trust level with the PHP server that you'll be running this from, so you need to install the AD Secure Certificate on the PHP server, or else you will get the infamous "Server is unwilling to perform" error.

## License
GNU GPL v3: http://www.gnu.org/licenses/gpl.txt
