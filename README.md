# go
Go Language Source for different purposes.  Not affiliated with Google.

===========================================================================
vsecure.go:  This program allows interacting with Hashicorp's Vault in an easy
way.  It uses an individuals Active Directory (or LDAP) credentials to interact
with the generic backend.  On first use, it will create the paths and policy
needed for the user, and assign it to their LDAP user in Vault.  In order to 
do this, the "userpass" authentication method must be enabled in Vault, and 
a username/password pair created with the following policy:

path "secret/usr/*" {
  policy = "write"
}

path "secret/usr" {
  policy = "write"
}

path "sys/policy/*" {
  policy = "write"
}

path "sys/policy" {
  policy = "read"
}

path "auth/ldap/*" {
  policy = "sudo"
}

path "auth/token/lookup-self" {
  policy = "read"
}

The Username/password pair must be added to the program in the space provided.
Note that this program uses a facility to keep track of keys the user adds to
their storage area, and in Vault .5, due out soon, this facility will be built
into the product.
============================================================================

